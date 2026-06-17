// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// tier2ConfidenceThreshold is the minimum computeConfidence score required
// before a repo with no matching seed agent is reported as a standalone
// GitHub-native agent. Below this threshold the signal is too weak to claim
// the repo hosts an AI agent (e.g. a bare utility script that happens to
// import an unrelated package).
const tier2ConfidenceThreshold = 0.3

// ── .specterignore handling ─────────────────────────────────────────────────

// loadSpecterIgnore fetches the org-wide ignore list from the `.specterignore`
// file in the org's `.github` repository. Each non-empty, non-comment line is
// a glob pattern (matched against repo name) for repos that Tier 2 discovery
// must never report on, even if they look like agents.
func (p *Plugin) loadSpecterIgnore(ctx context.Context, client *gogithub.Client) []string {
	var txt string
	p.fetchFileContent(ctx, client, p.ghCfg.Org, ".github", ".specterignore", &txt)
	if txt == "" {
		return nil
	}

	var patterns []string
	for _, line := range strings.Split(txt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// isIgnored reports whether repoName matches any pattern in patterns.
func isIgnored(repoName string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, err := path.Match(pat, repoName); err == nil && ok {
			return true
		}
	}
	return false
}

// ── Repo filtering ───────────────────────────────────────────────────────────

// shouldScanRepo applies the GitHubPluginConfig include/exclude/topic filters
// and .specterignore to decide whether Tier 2 discovery should consider repo.
// Archived repos are always skipped.
func (p *Plugin) shouldScanRepo(repo *gogithub.Repository, ignorePatterns []string) bool {
	name := repo.GetName()

	if repo.GetArchived() {
		return false
	}
	if isIgnored(name, ignorePatterns) {
		return false
	}

	for _, pat := range p.ghCfg.ExcludeRepos {
		if ok, err := path.Match(pat, name); err == nil && ok {
			return false
		}
	}

	if len(p.ghCfg.IncludeRepos) > 0 {
		matched := false
		for _, pat := range p.ghCfg.IncludeRepos {
			if ok, err := path.Match(pat, name); err == nil && ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(p.ghCfg.RequireTopics) > 0 {
		found := false
	outer:
		for _, t := range repo.Topics {
			for _, req := range p.ghCfg.RequireTopics {
				if strings.EqualFold(t, req) {
					found = true
					break outer
				}
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// ── Tier 3: entrypoint signal detection ─────────────────────────────────────

// tier3EntrypointFiles are candidate agent entrypoint files checked for
// agent-framework-shaped code even when no recognised dependency manifest
// declares a framework (e.g. a hand-rolled agent loop with no requirements.txt).
var tier3EntrypointFiles = []string{
	"main.py", "agent.py", "app.py", "handler.py", "run.py",
	"index.ts", "index.js", "main.ts", "main.js", "agent.ts", "agent.js",
}

// tier3AgentPatterns are code shapes commonly found in agent entrypoints
// regardless of which (if any) framework is declared in a manifest.
var tier3AgentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)class\s+\w*Agent\b`),
	regexp.MustCompile(`\bAgent\(`),
	regexp.MustCompile(`StateGraph`),
	regexp.MustCompile(`BaseTool`),
	regexp.MustCompile(`@tool\b`),
	regexp.MustCompile(`Crew\(`),
}

// detectEntrypointSignal fetches candidate entrypoint files and reports
// whether any of them contain an agent-shaped code pattern (Tier 3 signal).
func (p *Plugin) detectEntrypointSignal(ctx context.Context, client *gogithub.Client, org, repo string) bool {
	for _, f := range tier3EntrypointFiles {
		var txt string
		p.fetchFileContent(ctx, client, org, repo, f, &txt)
		if txt == "" {
			continue
		}
		for _, pat := range tier3AgentPatterns {
			if pat.MatchString(txt) {
				return true
			}
		}
	}
	return false
}

// ── Confidence scoring ───────────────────────────────────────────────────────

// computeConfidence scores how confident the scanner is that this repo hosts
// an AI agent, based on the strongest signal layer found:
//
//   - Tier 1 (intent declaration: .specter/manifest.yaml, AGENT.md, CLAUDE.md,
//     substantive README): +0.50 — explicit, human-authored declaration.
//   - Tier 2 (recognised agent framework dependency or config file): +0.35.
//   - Tier 3 (agent-shaped code pattern in an entrypoint file, no framework
//     declared): +0.15.
//
// Signals stack (a repo with both a manifest and a recognised framework scores
// higher than either alone), capped at 1.0.
func computeConfidence(content *GitHubRepoContent, framework string, entrypointSignal bool) float64 {
	var c float64
	if content.IntentText != "" {
		c += 0.50
	}
	if framework != "" {
		c += 0.35
	}
	if entrypointSignal {
		c += 0.15
	}
	if c > 1.0 {
		c = 1.0
	}
	return c
}

// ── Deployment infrastructure detection ─────────────────────────────────────

// detectDeploymentPlatform determines where the agent is (or will be) deployed.
//
// Priority order:
//  1. .specter/manifest.yaml deployment.target — a formal developer declaration;
//     returned as "DECLARED:<target>[:<status>]" regardless of CI/Dockerfile.
//  2. CI/CD workflow files — indicate an active, scripted deployment path.
//  3. Dockerfile — confirms the agent is containerised even if CI is absent.
//  4. "UNDETECTED" — no infrastructure signal found.
func (p *Plugin) detectDeploymentPlatform(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) string {
	// Priority 1: formal manifest declaration takes unconditional precedence.
	if content.ManifestDeploymentTarget != "" {
		platform := "DECLARED:" + content.ManifestDeploymentTarget
		if content.ManifestDeploymentStatus != "" {
			platform += ":" + content.ManifestDeploymentStatus
		}
		return platform
	}

	// Priority 2: CI/CD workflow signals.
	for _, wf := range content.WorkflowFiles {
		lower := strings.ToLower(wf.Content)
		switch {
		case strings.Contains(lower, "ecs") || strings.Contains(lower, "ecr"):
			return "AWS_ECS"
		case strings.Contains(lower, "lambda"):
			return "AWS_LAMBDA"
		case strings.Contains(lower, "eks") || strings.Contains(lower, "kubectl"):
			return "AWS_EKS"
		}
	}

	// Priority 3: Dockerfile.
	var dockerfile string
	p.fetchFileContent(ctx, client, org, repo, "Dockerfile", &dockerfile)
	if dockerfile != "" {
		return "CONTAINER"
	}

	return "UNDETECTED"
}

// ── Personal credential reference detection ─────────────────────────────────

// personalCredPatterns match environment variable names and inline values
// that indicate a personal/individual API key is expected, as opposed to a
// managed credential (IAM role, Secrets Manager reference, vault path).
var personalCredPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)OPENAI_API_KEY`),
	regexp.MustCompile(`(?i)ANTHROPIC_API_KEY`),
	regexp.MustCompile(`(?i)COHERE_API_KEY`),
	regexp.MustCompile(`(?i)HUGGINGFACE(_HUB)?_TOKEN`),
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{10,}`),
}

// managedCredentialPatterns indicate the repo sources credentials through a
// managed mechanism, which suppresses AGENT_PERSONAL_CREDENTIALS_DETECTED even
// if a personal-looking env var name is present (e.g. a placeholder that's
// actually populated from Secrets Manager at deploy time).
var managedCredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)secrets\s*manager`),
	regexp.MustCompile(`(?i)iam\s*role`),
	regexp.MustCompile(`(?i)assume\s*role`),
	regexp.MustCompile(`(?i)\bvault\b`),
	regexp.MustCompile(`(?i)parameter\s*store`),
}

// detectPersonalCredentials checks .env.example for personal API key
// references that are not explained by a managed-credential mechanism
// elsewhere in the repo's intent text or dependency manifests. Returns
// whether a finding should be raised and the matched env var name for
// evidence.
func (p *Plugin) detectPersonalCredentials(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) (bool, string) {
	var envExample string
	p.fetchFileContent(ctx, client, org, repo, ".env.example", &envExample)
	if envExample == "" {
		return false, ""
	}

	var matched string
	for _, pat := range personalCredPatterns {
		if m := pat.FindString(envExample); m != "" {
			matched = m
			break
		}
	}
	if matched == "" {
		return false, ""
	}

	combined := envExample + "\n" + content.IntentText + "\n" + content.RequirementsTxt + "\n" + content.PyprojectToml
	for _, pat := range managedCredentialPatterns {
		if pat.MatchString(combined) {
			return false, ""
		}
	}

	return true, matched
}

// ── Agent record construction ───────────────────────────────────────────────

// buildGitHubNativeAgentRecord constructs a standalone CanonicalAgentRecord for
// a repo with no AWS footprint. VisibilitySource is always "TIER_2" to
// distinguish these from AWS-discovered records enriched by Mode 1.
func buildGitHubNativeAgentRecord(
	orgID, orgName string,
	repo *gogithub.Repository,
	content *GitHubRepoContent,
	framework string,
	frameworkConfidence float64,
	isMCP bool,
	deploymentPlatform string,
	confidence float64,
	now time.Time,
) types.CanonicalAgentRecord {
	repoName := repo.GetName()
	externalID := fmt.Sprintf("github:%s/%s", orgName, repoName)

	// SHADOW only when the agent has no intent from any source AND no deployment
	// signal. Any intent (even README) or any detected/declared deployment
	// infrastructure is sufficient to classify the agent as DISCOVERED — it is
	// known, even if not yet formally registered.
	// Note: computeVisibility in main.go re-evaluates this after classification;
	// this initial value is used to set IsShadow before that pass runs.
	hasAnyIntent := content.IntentText != ""
	hasDeploySignal := deploymentPlatform != "" && deploymentPlatform != "UNDETECTED"
	visibilityClass := types.VisibilityClassShadow
	if hasAnyIntent || hasDeploySignal {
		visibilityClass = types.VisibilityClassDiscovered
	}

	functionalClass := types.FunctionalClassWorker
	if isMCP {
		functionalClass = types.FunctionalClassMCPServer
	}

	agent := types.CanonicalAgentRecord{
		StableID:   stableID(orgID, externalID),
		OrgID:      orgID,
		ExternalID: externalID,
		Name:       repoName,
		Platform:   "GITHUB",
		PublicURL:  repo.GetHTMLURL(),
		LastSeenAt: now,

		Framework:           framework,
		FrameworkConfidence: frameworkConfidence,

		VisibilityClass:  visibilityClass,
		FunctionalClass:  functionalClass,
		FederationStatus: types.FederationStatusUnregistered,
		IsShadow:         visibilityClass == types.VisibilityClassShadow,

		VisibilitySource: "TIER_2",

		RepoName:            repoName,
		RepoURL:             repo.GetHTMLURL(),
		DeploymentPlatform:  deploymentPlatform,
		DiscoveryConfidence: confidence,

		AlignmentTier: "UNKNOWN",
	}

	if content.IntentText != "" {
		agent.IntentStatement = firstSentence(content.IntentText)
		agent.IntentSource = content.IntentSource
		agent.IntentOwner = content.IntentOwner
		agent.IntentConfidence = intentConfidence(content.IntentSource)
	}

	return agent
}

// ── Findings generation ──────────────────────────────────────────────────────

// generateGitHubNativeFindings produces the Tier 2-specific findings for a
// GitHub-native agent record: undetected deployment infrastructure and personal
// credential references. MISSING_INTENT_DECLARATION and INTENT_OWNER_ABSENT are
// NOT generated here — the staticref analyzer (internal/analysis/staticref)
// already produces these for every agent in the combined result, including
// Tier 2 records appended by this plugin, so generating them here would
// duplicate findings.
func generateGitHubNativeFindings(
	agent types.CanonicalAgentRecord,
	hasPersonalCreds bool,
	credEvidence string,
	now time.Time,
) []types.FindingRecord {
	var findings []types.FindingRecord

	if agent.DeploymentPlatform == "UNDETECTED" {
		evidence, _ := json.Marshal(map[string]string{"repo": agent.RepoName})
		findings = append(findings, types.FindingRecord{
			RuleID:        "AGENT_DEPLOYMENT_UNDETECTED",
			Severity:      "LOW",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "No deployment infrastructure detected",
			Description:   fmt.Sprintf("Repository %s appears to host an AI agent but has no Dockerfile or CI/CD workflow indicating where it runs.", agent.RepoName),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "github",
		})
	}

	if hasPersonalCreds {
		evidence, _ := json.Marshal(map[string]string{"repo": agent.RepoName, "envVar": credEvidence})
		findings = append(findings, types.FindingRecord{
			RuleID:        "AGENT_PERSONAL_CREDENTIALS_DETECTED",
			Severity:      "MEDIUM",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "Agent expects a personal API credential",
			Description:   fmt.Sprintf("Repository %s's .env.example references %s with no managed-credential mechanism (Secrets Manager, IAM role, vault) found in the repo.", agent.RepoName, credEvidence),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "github",
		})
	}

	return findings
}

// ── Tier 2 repo scan ──────────────────────────────────────────────────────────

// scanRepoTier2 scans a repo that did not match any Phase 1 (AWS) seed agent.
// If the combined discovery signals clear tier2ConfidenceThreshold, it returns
// a standalone GitHub-native agent record and its findings; otherwise (nil, nil).
func (p *Plugin) scanRepoTier2(ctx context.Context, client *gogithub.Client, repo *gogithub.Repository) (*types.CanonicalAgentRecord, []types.FindingRecord) {
	now := time.Now().UTC()
	repoName := repo.GetName()
	orgName := p.ghCfg.Org

	content := &GitHubRepoContent{}

	p.fetchFileContent(ctx, client, orgName, repoName, "requirements.txt", &content.RequirementsTxt)
	p.fetchFileContent(ctx, client, orgName, repoName, "pyproject.toml", &content.PyprojectToml)
	p.fetchFileContent(ctx, client, orgName, repoName, "package.json", &content.PackageJSON)
	p.fetchFileContent(ctx, client, orgName, repoName, "langgraph.json", &content.LangGraphJSON)
	p.fetchFileContent(ctx, client, orgName, repoName, "mcp.json", &content.MCPJson)

	_, _, crewResp, _ := client.Repositories.GetContents(ctx, orgName, repoName, ".crew", nil)
	if crewResp != nil && crewResp.StatusCode == 200 {
		content.CrewDir = true
	}

	p.extractIntentDeclaration(ctx, client, orgName, repoName, content)

	allManifest := content.RequirementsTxt + "\n" + content.PyprojectToml + "\n" + content.PackageJSON
	framework, frameworkConfidence, isMCP := detectFrameworkFromManifest(allManifest)

	switch {
	case content.LangGraphJSON != "":
		framework, frameworkConfidence, isMCP = "LangGraph", 0.97, false
	case content.CrewDir:
		framework, frameworkConfidence, isMCP = "CrewAI", 0.95, false
	case content.MCPJson != "":
		framework, frameworkConfidence, isMCP = "MCP SDK", 0.98, true
	}

	entrypointSignal := false
	if framework == "" {
		entrypointSignal = p.detectEntrypointSignal(ctx, client, orgName, repoName)
	}

	confidence := computeConfidence(content, framework, entrypointSignal)
	if confidence < tier2ConfidenceThreshold {
		return nil, nil
	}

	p.scanWorkflows(ctx, client, orgName, repoName, content)
	deploymentPlatform := p.detectDeploymentPlatform(ctx, client, orgName, repoName, content)
	hasPersonalCreds, credEvidence := p.detectPersonalCredentials(ctx, client, orgName, repoName, content)

	agent := buildGitHubNativeAgentRecord(p.cfg.OrgID, orgName, repo, content, framework, frameworkConfidence, isMCP, deploymentPlatform, confidence, now)
	findings := generateGitHubNativeFindings(agent, hasPersonalCreds, credEvidence, now)

	return &agent, findings
}
