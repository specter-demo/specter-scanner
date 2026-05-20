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
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/specter-demo/specter-scanner/internal/blast"
	"github.com/specter-demo/specter-scanner/internal/chain"
	"github.com/specter-demo/specter-scanner/internal/classify"
	"github.com/specter-demo/specter-scanner/internal/config"
	"github.com/specter-demo/specter-scanner/internal/ingest"
	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/protocol/a2a"
	"github.com/specter-demo/specter-scanner/internal/protocol/mcp"
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

	scanID := uuid.New().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Configure plugins
	if err := configurePlugins(cfg); err != nil {
		log.Fatalf("configure plugins: %v", err)
	}

	// Run scan
	result, err := runScan(ctx, cfg, scanID)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	// Protocol analysis (A2A + MCP)
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

	// Classification pass
	for i := range result.Agents {
		agent := &result.Agents[i]

		// Framework detection (combine layers)
		*agent = classify.DetectFramework(*agent, nil)

		// Functional class from edge degrees
		agent.FunctionalClass = classify.ClassifyFunctional(agent, result.Edges)

		// Visibility class
		agent.VisibilityClass = computeVisibility(agent)
		agent.IsShadow = agent.VisibilityClass == types.VisibilityClassShadow

		// Risk score
		agent.RiskScore = classify.ComputeRiskScore(agent, result.Edges)
	}

	// Blast radius computation
	result.Agents = blast.Compute(result.Agents, result.Edges)

	// Delegation chain reconstruction
	chains := chain.Reconstruct(result.Agents, result.Edges, result.Events)

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
		// Write to stdout
		if err := writeReport(cfg.OutputFormat, payload); err != nil {
			log.Fatalf("write report: %v", err)
		}
		return
	}

	// Post to platform
	if err := postToplatform(ctx, cfg, payload); err != nil {
		log.Fatalf("post to platform: %v", err)
	}
	log.Printf("Scan %s posted to platform. %d agents, %d findings.", scanID, len(result.Agents), len(result.Findings))
}

func configurePlugins(cfg *config.ScannerConfig) error {
	plugins := plugin.All()

	for _, p := range plugins {
		var rawConfig []byte

		switch p.Name() {
		case "aws":
			awsCfg := map[string]interface{}{
				"standaloneMode": cfg.NoPlatform,
				"awsProfile":     cfg.AWSProfile,
				"region":         cfg.AWSRegion,
			}
			var err error
			rawConfig, err = json.Marshal(awsCfg)
			if err != nil {
				return fmt.Errorf("marshal aws config: %w", err)
			}
		case "github":
			ghCfg := map[string]interface{}{
				"token": cfg.GitHubToken,
				"org":   cfg.GitHubOrg,
			}
			var err error
			rawConfig, err = json.Marshal(ghCfg)
			if err != nil {
				return fmt.Errorf("marshal github config: %w", err)
			}
		}

		if err := p.Configure(plugin.PluginConfig{
			OrgID:     cfg.OrgID,
			OrgSlug:   cfg.OrgSlug,
			PluginType: p.Name(),
			RawConfig: rawConfig,
		}); err != nil {
			return fmt.Errorf("configure plugin %s: %w", p.Name(), err)
		}
	}
	return nil
}

func runScan(ctx context.Context, cfg *config.ScannerConfig, _ string) (*combinedScanResult, error) {
	var activePlugins []plugin.ScanPlugin
	if cfg.PluginFilter != "" {
		p, err := plugin.Get(cfg.PluginFilter)
		if err != nil {
			return nil, fmt.Errorf("plugin %q not found", cfg.PluginFilter)
		}
		activePlugins = []plugin.ScanPlugin{p}
	} else {
		activePlugins = plugin.All()
	}

	type pluginResult struct {
		name     string
		result   *plugin.ScanResult
		err      error
	}

	resultCh := make(chan pluginResult, len(activePlugins))
	var wg sync.WaitGroup

	for _, p := range activePlugins {
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

	combined := &combinedScanResult{}
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
	}

	return combined, nil
}

type combinedScanResult struct {
	Agents   []types.CanonicalAgentRecord
	Edges    []types.AgentEdgeRecord
	Events   []types.NormalizedEvent
	Findings []types.FindingRecord
}

func computeVisibility(agent *types.CanonicalAgentRecord) types.VisibilityClass {
	// Shadow: no owner tag and no governance metadata
	if agent.OwnerTag == "" && agent.AgentClassTag == "" {
		return types.VisibilityClassShadow
	}
	// Governed: has owner tag
	if agent.OwnerTag != "" {
		return types.VisibilityClassGoverned
	}
	return types.VisibilityClassDiscovered
}

func writeReport(format string, payload types.ScanPayload) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	case "html":
		return writeHTMLReport(os.Stdout, payload)
	default:
		return fmt.Errorf("unknown output format: %q", format)
	}
}

func writeHTMLReport(w io.Writer, payload types.ScanPayload) error {
	criticalCount := 0
	highCount := 0
	for _, f := range payload.Findings {
		switch f.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Specter Scanner Report — %s</title>
<style>body{font-family:sans-serif;margin:2rem;}table{border-collapse:collapse;width:100%%;}th,td{border:1px solid #ccc;padding:0.5rem;text-align:left;}th{background:#f0f0f0;}.CRITICAL{color:#c00;font-weight:bold;}.HIGH{color:#e66;}.MEDIUM{color:#e90;}.LOW{color:#090;}</style>
</head><body>
<h1>Specter Scanner Report</h1>
<p>Scan ID: <code>%s</code> | Org: <code>%s</code> | Scanned at: %s | Version: %s</p>
<p>%d agents discovered &bull; %d findings (%d CRITICAL, %d HIGH)</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Agent</th><th>Title</th></tr>
`, payload.OrgID, payload.ScanID, payload.OrgID, payload.ScannedAt.Format(time.RFC3339), payload.ScannerVersion,
		len(payload.Agents), len(payload.Findings), criticalCount, highCount)

	for _, f := range payload.Findings {
		fmt.Fprintf(w, "<tr><td class=%q>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			f.Severity, f.Severity, f.RuleID, f.AgentName, f.Title)
	}

	fmt.Fprintf(w, `</table>
<h2>Agents (%d)</h2>
<table><tr><th>Name</th><th>Platform</th><th>Framework</th><th>Visibility</th><th>Risk</th></tr>
`, len(payload.Agents))

	for _, ag := range payload.Agents {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>\n",
			ag.Name, ag.Platform, ag.Framework, ag.VisibilityClass, ag.RiskScore)
	}

	fmt.Fprintf(w, "</table></body></html>\n")
	return nil
}

func postToplatform(ctx context.Context, cfg *config.ScannerConfig, payload types.ScanPayload) error {
	data, sig, err := ingest.MarshalSigned(payload, cfg.APIKey)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := cfg.PlatformURL + "/v1/scanner/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("X-Specter-Signature", sig)
	req.Header.Set("X-Scanner-Version", Version)

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
