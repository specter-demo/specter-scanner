// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main is the Specter AI Agent governance scanner entry point.
// It wires together all plugins, protocol analyzers, and classification passes,
// then either writes a JSON/HTML report to stdout (--no-platform) or posts
// the ingest payload to the Specter platform.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/specter-demo/specter-scanner/internal/analysis/staticref"
	"github.com/specter-demo/specter-scanner/internal/blast"
	"github.com/specter-demo/specter-scanner/internal/chain"
	"github.com/specter-demo/specter-scanner/internal/classify"
	"github.com/specter-demo/specter-scanner/internal/config"
	"github.com/specter-demo/specter-scanner/internal/ingest"
	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/protocol/a2a"
	"github.com/specter-demo/specter-scanner/internal/protocol/mcp"
	"github.com/specter-demo/specter-scanner/internal/report"
	"github.com/specter-demo/specter-scanner/internal/types"

	// Register plugins via init()
	_ "github.com/specter-demo/specter-scanner/internal/plugin/aws"
	_ "github.com/specter-demo/specter-scanner/internal/plugin/github"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	// Parse --version before full flag parse
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("specter-scanner %s\n", Version)
			os.Exit(0)
		}
	}

	cfg := config.Parse()
	cfg.Version = Version

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if cfg.LogLevel == "debug" {
		log.SetOutput(os.Stderr)
	} else {
		// In non-debug mode, only log warnings/errors to stderr
		log.SetOutput(os.Stderr)
	}

	// Validate
	if !cfg.NoPlatform && cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "error: --api-key or SPECTER_API_KEY is required (or use --no-platform)")
		flag.Usage()
		os.Exit(1)
	}

	// In platform mode, use the scan ID pre-created by the platform so that
	// phase updates land on the right record. Fall back to a new UUID in
	// standalone mode (--no-platform) or when the env var is absent.
	scanID := os.Getenv("SPECTER_SCAN_ID")
	if scanID == "" {
		scanID = uuid.New().String()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Fetch platform config (in platform mode) to get plugin settings including GitHub org.
	var platformCfg *config.PlatformConfig
	if !cfg.NoPlatform && cfg.PlatformURL != "" && cfg.APIKey != "" {
		var err error
		platformCfg, err = config.FetchPlatformConfig(cfg.PlatformURL, cfg.APIKey)
		if err != nil {
			log.Printf("WARNING: could not fetch platform config: %v — falling back to CLI flags", err)
		} else {
			log.Printf("Platform config fetched: %d plugin(s)", len(platformCfg.Plugins))
		}
	}

	// Configure plugins
	if err := configurePlugins(cfg, platformCfg); err != nil {
		log.Fatalf("configure plugins: %v", err)
	}

	// ── Phase: AWS_DISCOVERY ─────────────────────────────────────────────────
	postPhaseUpdate(cfg, scanID, "AWS_DISCOVERY", "RUNNING", "Discovering agents in AWS", 0, 0, 0)
	phaseStart := time.Now()
	result, err := runScan(ctx, cfg, scanID, platformCfg)
	if err != nil {
		postPhaseUpdate(cfg, scanID, "AWS_DISCOVERY", "FAILED", err.Error(), 0, 0, int(time.Since(phaseStart).Milliseconds()))
		log.Fatalf("scan failed: %v", err)
	}
	postPhaseUpdate(cfg, scanID, "AWS_DISCOVERY", "COMPLETE", "", len(result.Agents), len(result.Findings), int(time.Since(phaseStart).Milliseconds()))

	if checkCancelled(cfg, scanID) {
		log.Printf("Scan %s cancelled by user after AWS_DISCOVERY", scanID)
		os.Exit(0)
	}

	// ── Phase: GITHUB_ENRICHMENT — already executed inside runScan Phase 2 ──
	// runScan posts its own GITHUB_ENRICHMENT updates; nothing to do here.

	if checkCancelled(cfg, scanID) {
		log.Printf("Scan %s cancelled by user after GITHUB_ENRICHMENT", scanID)
		os.Exit(0)
	}

	// ── Phase: PROTOCOL_ANALYSIS ─────────────────────────────────────────────
	postPhaseUpdate(cfg, scanID, "PROTOCOL_ANALYSIS", "RUNNING", "Probing A2A and MCP endpoints", 0, 0, 0)
	phaseStart = time.Now()

	a2aAnalyzer := a2a.New(scanID, cfg.RateLimit)
	mcpAnalyzer := mcp.New()

	a2aFindings, err := a2aAnalyzer.Analyze(ctx, result.Agents, cfg.OrgSlug)
	if err != nil {
		log.Printf("a2a analysis error: %v", err)
	}
	result.Findings = append(result.Findings, a2aFindings...)

	mcpFindings, err := mcpAnalyzer.Analyze(ctx, result.Agents, cfg.OrgSlug)
	if err != nil {
		log.Printf("mcp analysis error: %v", err)
	}
	result.Findings = append(result.Findings, mcpFindings...)

	postPhaseUpdate(cfg, scanID, "PROTOCOL_ANALYSIS", "COMPLETE", "", 0, len(a2aFindings)+len(mcpFindings), int(time.Since(phaseStart).Milliseconds()))

	if checkCancelled(cfg, scanID) {
		log.Printf("Scan %s cancelled by user after PROTOCOL_ANALYSIS", scanID)
		os.Exit(0)
	}

	// ── Phase: CLASSIFICATION ────────────────────────────────────────────────
	postPhaseUpdate(cfg, scanID, "CLASSIFICATION", "RUNNING", "Classifying agents and computing risk", 0, 0, 0)
	phaseStart = time.Now()

	// Static reference analysis
	staticAnalyzer := staticref.New(cfg.OrgID)
	staticEdges, staticFindings := staticAnalyzer.Analyze(ctx, result.Agents, result.StaticRefs, result.Edges)
	result.Edges = append(result.Edges, staticEdges...)
	result.Findings = append(result.Findings, staticFindings...)

	// Classification pass
	for i := range result.Agents {
		agent := &result.Agents[i]
		*agent = classify.DetectFramework(*agent, nil)
		agent.FunctionalClass = classify.ClassifyFunctional(agent, result.Edges)
		agent.VisibilityClass = computeVisibility(agent)
		agent.IsShadow = agent.VisibilityClass == types.VisibilityClassShadow
		agent.RiskScore = classify.ComputeRiskScore(agent, result.Edges)
	}

	// Blast radius computation
	result.Agents = blast.Compute(result.Agents, result.Edges)

	// Delegation chain reconstruction
	chains := chain.Reconstruct(result.Agents, result.Edges, result.Events)

	postPhaseUpdate(cfg, scanID, "CLASSIFICATION", "COMPLETE", "", len(result.Agents), len(result.Findings), int(time.Since(phaseStart).Milliseconds()))

	// Safety net: drop any finding that references an unknown agent stableId.
	// This catches pipeline bugs loudly rather than letting orphan findings
	// reach the platform or confuse the report.
	result.Findings = validateFindings(result.Agents, result.Findings)

	// Assemble payload
	payload := ingest.Assemble(
		scanID,
		cfg.OrgID,
		Version,
		result.Agents,
		result.Edges,
		result.Findings,
		chains,
	)

	if cfg.NoPlatform {
		if err := writeStandaloneReport(cfg, payload, Version); err != nil {
			log.Fatalf("write report: %v", err)
		}
		return
	}

	// ── Phase: POSTING ───────────────────────────────────────────────────────
	postPhaseUpdate(cfg, scanID, "POSTING", "RUNNING", "Sending results to platform", 0, 0, 0)
	phaseStart = time.Now()

	if err := postToplatform(ctx, cfg, payload); err != nil {
		postPhaseUpdate(cfg, scanID, "POSTING", "FAILED", err.Error(), 0, 0, int(time.Since(phaseStart).Milliseconds()))
		log.Fatalf("post to platform: %v", err)
	}

	postPhaseUpdate(cfg, scanID, "POSTING", "COMPLETE", "", len(result.Agents), len(result.Findings), int(time.Since(phaseStart).Milliseconds()))
	log.Printf("Scan %s posted to platform. %d agents, %d findings.", scanID, len(result.Agents), len(result.Findings))
}

// postPhaseUpdate sends a phase progress update to the platform.
// In standalone mode (cfg.NoPlatform) or when no scanID is set, it is a no-op.
func postPhaseUpdate(cfg *config.ScannerConfig, scanID, phase, status, message string, agentsFound, findingsFound, durationMs int) {
	if cfg.NoPlatform || cfg.PlatformURL == "" || cfg.APIKey == "" || scanID == "" {
		return
	}

	body := map[string]interface{}{
		"phase":        phase,
		"status":       status,
		"message":      message,
		"agentsFound":  agentsFound,
		"findingsFound": findingsFound,
		"durationMs":   durationMs,
	}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("postPhaseUpdate: marshal error: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/scans/%s/progress", cfg.PlatformURL, scanID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("postPhaseUpdate: build request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("postPhaseUpdate: request error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		log.Printf("postPhaseUpdate: platform returned %d: %s", resp.StatusCode, string(b))
	}
}

// checkCancelled polls the platform for the current scan status and returns
// true if the scan has been cancelled by the user. In standalone mode or when
// no scan ID is set, it always returns false.
func checkCancelled(cfg *config.ScannerConfig, scanID string) bool {
	if cfg.NoPlatform || cfg.PlatformURL == "" || cfg.APIKey == "" || scanID == "" {
		return false
	}

	url := fmt.Sprintf("%s/api/v1/scans/%s/status", cfg.PlatformURL, scanID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("checkCancelled: build request error: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("checkCancelled: request error: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Status == "CANCELLED"
}

func configurePlugins(cfg *config.ScannerConfig, platformCfg *config.PlatformConfig) error {
	plugins := plugin.All()

	for _, p := range plugins {
		var rawConfig []byte

		switch p.Name() {
		case "aws":
			awsCfg := map[string]interface{}{
				"standaloneMode": cfg.NoPlatform,
				"awsProfile":     cfg.AWSProfile,
				"region":         cfg.AWSRegion,
				// Cross-account role for cloud-hosted scanning.
				// Empty in standalone mode; set via SPECTER_READONLY_ROLE_ARN in ECS.
				"roleArn":    config.ReadonlyRoleARN(),
				"externalId": config.ReadonlyExternalID(),
			}
			var err error
			rawConfig, err = json.Marshal(awsCfg)
			if err != nil {
				return fmt.Errorf("marshal aws config: %w", err)
			}

		case "github":
			// Platform config takes precedence — org and discovery settings
			// come from the Plugin record stored in the platform DB.
			// Authentication (token) comes from env vars via getGitHubToken().
			if platformCfg != nil {
				if ghPlugin := platformCfg.FindPlugin("GITHUB"); ghPlugin != nil {
					var err error
					rawConfig, err = ghPlugin.RawConfig()
					if err != nil {
						return fmt.Errorf("marshal github platform config: %w", err)
					}
					org, _ := ghPlugin.Config["org"].(string)
					log.Printf("[config] GitHub plugin configured from platform: org=%s", org)
					break
				}
			}
			// Fallback: CLI flags for standalone mode
			if cfg.GitHubOrg == "" {
				log.Printf("[config] GitHub plugin: no platform config and no --github-org flag — skipping")
				continue
			}
			ghCfg := map[string]interface{}{
				"token":          cfg.GitHubToken,
				"org":            cfg.GitHubOrg,
				"tier2Discovery": true,
				"excludeRepos": []string{
					"specter-scanner",
					"specter-platform",
					"*-archived",
					"*-template",
				},
			}
			var err error
			rawConfig, err = json.Marshal(ghCfg)
			if err != nil {
				return fmt.Errorf("marshal github config: %w", err)
			}
		}

		if err := p.Configure(plugin.PluginConfig{
			OrgID:      cfg.OrgID,
			OrgSlug:    cfg.OrgSlug,
			PluginType: p.Name(),
			RawConfig:  rawConfig,
		}); err != nil {
			return fmt.Errorf("configure plugin %s: %w", p.Name(), err)
		}
	}
	return nil
}

// runScan executes plugins in two sequential phases so that the GitHub plugin
// can enrich agents that were already discovered by Phase 1 (e.g., AWS) rather
// than creating duplicate GITHUB-platform records.
//
// Phase 1: all non-GitHub plugins run in parallel.
// Phase 2: the GitHub plugin is reconfigured with Phase 1 agents as SeedAgents,
// then run. Its returned agents are merged back into the Phase 1 set (in-place
// update by stableId) rather than appended, preventing duplicates.
func runScan(ctx context.Context, cfg *config.ScannerConfig, scanID string, platformCfg *config.PlatformConfig) (*combinedScanResult, error) {
	var allPlugins []plugin.ScanPlugin
	if cfg.PluginFilter != "" {
		p, err := plugin.Get(cfg.PluginFilter)
		if err != nil {
			return nil, fmt.Errorf("plugin %q not found", cfg.PluginFilter)
		}
		allPlugins = []plugin.ScanPlugin{p}
	} else {
		allPlugins = plugin.All()
	}

	// Separate GitHub plugin from the rest.
	var phase1Plugins []plugin.ScanPlugin
	var githubPlugin plugin.ScanPlugin
	for _, p := range allPlugins {
		if p.Name() == "github" {
			githubPlugin = p
		} else {
			phase1Plugins = append(phase1Plugins, p)
		}
	}

	type pluginResult struct {
		name   string
		result *plugin.ScanResult
		err    error
	}

	combined := &combinedScanResult{}

	// ── Phase 1: non-GitHub plugins in parallel ──────────────────────────────
	if len(phase1Plugins) > 0 {
		resultCh := make(chan pluginResult, len(phase1Plugins))
		var wg sync.WaitGroup
		for _, p := range phase1Plugins {
			wg.Add(1)
			go func(p plugin.ScanPlugin) {
				defer wg.Done()
				log.Printf("plugin %s: starting scan", p.Name())
				start := time.Now()
				r, err := p.Scan(ctx)
				log.Printf("plugin %s: done in %v", p.Name(), time.Since(start))
				resultCh <- pluginResult{name: p.Name(), result: r, err: err}
			}(p)
		}
		wg.Wait()
		close(resultCh)
		for pr := range resultCh {
			if pr.err != nil {
				log.Printf("plugin %s error: %v", pr.name, pr.err)
				continue
			}
			if pr.result == nil {
				continue
			}
			combined.Agents = append(combined.Agents, pr.result.Agents...)
			combined.Edges = append(combined.Edges, pr.result.Edges...)
			combined.Events = append(combined.Events, pr.result.Events...)
			combined.Findings = append(combined.Findings, pr.result.Findings...)
			combined.StaticRefs = append(combined.StaticRefs, pr.result.StaticRefs...)
		}
	}

	// ── Phase 2: GitHub plugin with seed agents from Phase 1 ─────────────────
	if githubPlugin != nil {
		postPhaseUpdate(cfg, scanID, "GITHUB_ENRICHMENT", "RUNNING", "Enriching agents with GitHub data", 0, 0, 0)
		ghPhaseStart := time.Now()

		// Phase 2 GitHub config: platform config takes precedence (same as Phase 1).
		var ghRawCfg []byte
		if platformCfg != nil {
			if ghPlugin := platformCfg.FindPlugin("GITHUB"); ghPlugin != nil {
				var err error
				ghRawCfg, err = ghPlugin.RawConfig()
				if err != nil {
					return nil, fmt.Errorf("marshal github platform config for phase 2: %w", err)
				}
			}
		}
		if ghRawCfg == nil {
			// Fallback to CLI flags for standalone mode
			var err error
			ghRawCfg, err = json.Marshal(map[string]interface{}{
				"token":          cfg.GitHubToken,
				"org":            cfg.GitHubOrg,
				"tier2Discovery": true,
				"excludeRepos": []string{
					"specter-scanner",
					"specter-platform",
					"*-archived",
					"*-template",
				},
			})
			if err != nil {
				return nil, fmt.Errorf("marshal github config for phase 2: %w", err)
			}
		}
		if err := githubPlugin.Configure(plugin.PluginConfig{
			OrgID:      cfg.OrgID,
			OrgSlug:    cfg.OrgSlug,
			PluginType: "github",
			RawConfig:  ghRawCfg,
			SeedAgents: combined.Agents, // agents discovered in Phase 1
			SeedEdges:  combined.Edges,  // edges discovered in Phase 1 (for alignment scoring)
		}); err != nil {
			log.Printf("plugin github: reconfigure error: %v", err)
			postPhaseUpdate(cfg, scanID, "GITHUB_ENRICHMENT", "FAILED", err.Error(), 0, 0, int(time.Since(ghPhaseStart).Milliseconds()))
		} else {
			log.Printf("plugin github: starting scan")
			start := time.Now()
			r, err := githubPlugin.Scan(ctx)
			log.Printf("plugin github: done in %v", time.Since(start))
			if err != nil {
				log.Printf("plugin github error: %v", err)
				postPhaseUpdate(cfg, scanID, "GITHUB_ENRICHMENT", "FAILED", err.Error(), 0, len(combined.Findings), int(time.Since(ghPhaseStart).Milliseconds()))
			} else if r != nil {
				// Enrich Phase 1 agents in-place with GitHub data (intent, alignment,
				// framework). The GitHub plugin returns copies of matched seed agents
				// with enriched fields; we replace the Phase 1 record by stableId.
				// We do NOT duplicate these as new agents.
				//
				// Tier 2 discovery additionally returns standalone agent records for
				// repos with no AWS footprint (VisibilitySource == "TIER_2", new
				// stableIds not present in combined.Agents) — these are appended.
				if len(r.Agents) > 0 {
					existingStableIDs := make(map[string]bool, len(combined.Agents))
					for _, a := range combined.Agents {
						existingStableIDs[a.StableID] = true
					}

					ghByStableID := make(map[string]types.CanonicalAgentRecord, len(r.Agents))
					for _, a := range r.Agents {
						ghByStableID[a.StableID] = a
					}
					for i := range combined.Agents {
						if enriched, ok := ghByStableID[combined.Agents[i].StableID]; ok {
							combined.Agents[i] = enriched
						}
					}

					for _, a := range r.Agents {
						if !existingStableIDs[a.StableID] {
							combined.Agents = append(combined.Agents, a)
						}
					}
				}
				combined.Edges = append(combined.Edges, r.Edges...)
				combined.Events = append(combined.Events, r.Events...)
				combined.Findings = append(combined.Findings, r.Findings...)
				combined.StaticRefs = append(combined.StaticRefs, r.StaticRefs...)
				postPhaseUpdate(cfg, scanID, "GITHUB_ENRICHMENT", "COMPLETE", "", len(combined.Agents), len(combined.Findings), int(time.Since(ghPhaseStart).Milliseconds()))
			} else {
				// r is nil — no GitHub data, phase still completes successfully
				postPhaseUpdate(cfg, scanID, "GITHUB_ENRICHMENT", "COMPLETE", "No GitHub repositories found", len(combined.Agents), 0, int(time.Since(ghPhaseStart).Milliseconds()))
			}
		}
	}

	return combined, nil
}

type combinedScanResult struct {
	Agents     []types.CanonicalAgentRecord
	Edges      []types.AgentEdgeRecord
	Events     []types.NormalizedEvent
	Findings   []types.FindingRecord
	StaticRefs []types.StaticRef
}

// validateFindings removes findings with empty or dangling AgentStableID values.
// Any finding that survives this check is guaranteed to have a corresponding
// agent record in the payload; the platform rejects dangling references.
func validateFindings(agents []types.CanonicalAgentRecord, findings []types.FindingRecord) []types.FindingRecord {
	validStableIDs := make(map[string]string, len(agents))
	for _, a := range agents {
		validStableIDs[a.StableID] = a.Name
	}
	out := findings[:0]
	for _, f := range findings {
		if f.AgentStableID == "" {
			log.Printf("PIPELINE ERROR: finding %s has empty AgentStableID — dropping", f.RuleID)
			continue
		}
		if _, ok := validStableIDs[f.AgentStableID]; !ok {
			log.Printf("PIPELINE ERROR: finding %s references unknown AgentStableID %s — dropping", f.RuleID, f.AgentStableID)
			continue
		}
		out = append(out, f)
	}
	return out
}

func computeVisibility(agent *types.CanonicalAgentRecord) types.VisibilityClass {
	// GOVERNED: AWS resource tag explicitly names an owner team.
	if agent.OwnerTag != "" {
		return types.VisibilityClassGoverned
	}

	// DISCOVERED: agent is confirmed and has some governance signal — either
	// a formal intent declaration (.specter/manifest.yaml, AGENT.md, CLAUDE.md)
	// or detected/declared deployment infrastructure. README-only intent is
	// informal and does not satisfy this threshold.
	hasFormalIntent := agent.IntentSource == "MANIFEST" ||
		agent.IntentSource == "AGENT_MD" ||
		agent.IntentSource == "CLAUDE_MD"
	hasDeployInfra := agent.DeploymentPlatform != "" &&
		agent.DeploymentPlatform != "UNDETECTED"
	if agent.AgentClassTag != "" || hasFormalIntent || hasDeployInfra {
		return types.VisibilityClassDiscovered
	}

	// SHADOW: high-confidence agent signal (framework/dependency) but no formal
	// intent file and no detectable/declared deployment infrastructure.
	return types.VisibilityClassShadow
}

// writeStandaloneReport generates a report file and prints a summary to stdout.
// Exits with code 1 if CRITICAL findings are present (quality gate mode).
func writeStandaloneReport(cfg *config.ScannerConfig, payload types.ScanPayload, version string) error {
	format := cfg.OutputFormat
	if format == "" {
		format = "html"
	}

	// Determine output file path
	outPath := cfg.OutputFile
	if outPath == "" {
		if format == "json" {
			outPath = "specter-report.json"
		} else {
			outPath = "specter-report.html"
		}
	}
	// Normalise extension for json output
	if format == "json" && !strings.HasSuffix(outPath, ".json") {
		outPath = strings.TrimSuffix(outPath, ".html") + ".json"
	}

	var fileBytes []byte
	var err error

	switch format {
	case "json":
		fileBytes, err = json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
	case "html", "":
		fileBytes, err = report.GenerateHTML(payload, version)
		if err != nil {
			return fmt.Errorf("generate html: %w", err)
		}
	default:
		return fmt.Errorf("unknown output format %q — use html or json", format)
	}

	if err := os.WriteFile(outPath, fileBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	// Print summary to stdout
	criticalCount := report.CountBySeverity(payload.Findings, "CRITICAL")
	highCount     := report.CountBySeverity(payload.Findings, "HIGH")
	mediumCount   := report.CountBySeverity(payload.Findings, "MEDIUM")
	lowCount      := report.CountBySeverity(payload.Findings, "LOW")

	fmt.Printf("\nSpecter Scanner — Scan Complete\n")
	fmt.Printf("════════════════════════════════\n")
	fmt.Printf("Agents discovered:  %d\n", len(payload.Agents))
	fmt.Printf("Total findings:     %d\n", len(payload.Findings))
	fmt.Printf("  CRITICAL:         %d\n", criticalCount)
	fmt.Printf("  HIGH:             %d\n", highCount)
	fmt.Printf("  MEDIUM:           %d\n", mediumCount)
	fmt.Printf("  LOW:              %d\n", lowCount)
	fmt.Printf("\nReport written to:  %s\n", outPath)

	// Quality gate: exit 1 if CRITICAL findings detected
	if criticalCount > 0 {
		fmt.Printf("\n⚠  CRITICAL findings detected — quality gate FAILED\n")
		fmt.Printf("   Resolve all CRITICAL findings before deploying.\n")
		os.Exit(1)
	}

	return nil
}

func postToplatform(ctx context.Context, cfg *config.ScannerConfig, payload types.ScanPayload) error {
	data, sig, err := ingest.MarshalSigned(payload, cfg.APIKey)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := cfg.PlatformURL + "/api/v1/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("X-Specter-Signature", sig)
	req.Header.Set("X-Specter-Scanner-Version", Version)
	req.Header.Set("X-Specter-Scan-Id", payload.ScanID)
	req.Header.Set("X-Specter-Org-Id", payload.OrgID)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("platform returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
