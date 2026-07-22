// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package github implements the GitHub scanner plugin.
// It scans repositories in a GitHub organization for agent code,
// committed secrets, and workflow credential hygiene.
package github

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	gogithub "github.com/google/go-github/v66/github"
	"golang.org/x/oauth2"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/plugin/shared"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// GitHubPluginConfig holds GitHub-specific configuration.
type GitHubPluginConfig struct {
	Token      string `json:"token"`
	Org        string `json:"org"`
	AppID      int64  `json:"appId"`
	PrivateKey string `json:"privateKey"`

	// Tier 2 GitHub-native discovery configuration.
	IncludeRepos   []string `json:"includeRepos,omitempty"`  // glob patterns; if set, only matching repos are eligible
	ExcludeRepos   []string `json:"excludeRepos,omitempty"`  // glob patterns; matching repos are always skipped
	RequireTopics  []string `json:"requireTopics,omitempty"` // if set, repo must have at least one of these topics
	ScanPaths      []string `json:"scanPaths,omitempty"`     // additional subdirectories to check for entrypoint files
	Tier2Discovery bool     `json:"tier2Discovery"`          // enable standalone GITHUB-platform agent records for unmatched repos
}

// Plugin is the GitHub scanner plugin.
type Plugin struct {
	cfg   plugin.PluginConfig
	ghCfg GitHubPluginConfig
}

func init() {
	plugin.Register(&Plugin{})
}

// credentialErrorSignatures are substrings of go-github/HTTP error messages
// that indicate an authentication failure (bad/expired/missing token), as
// opposed to a successful call that simply found zero results.
var credentialErrorSignatures = []string{
	"401",
	"Bad credentials",
	"Requires authentication",
}

func isCredentialError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sig := range credentialErrorSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

func (p *Plugin) Name() string { return "github" }

func (p *Plugin) Configure(cfg plugin.PluginConfig) error {
	p.cfg = cfg
	if len(cfg.RawConfig) > 0 {
		if err := json.Unmarshal(cfg.RawConfig, &p.ghCfg); err != nil {
			return fmt.Errorf("github: invalid config: %w", err)
		}
	}
	if p.ghCfg.Org == "" {
		p.ghCfg.Org = cfg.OrgSlug
	}
	return nil
}

func (p *Plugin) buildClient(ctx context.Context) (*gogithub.Client, error) {
	token, err := getGitHubToken()
	if err != nil {
		return nil, err
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return gogithub.NewClient(tc), nil
}

// getGitHubToken returns an access token for the GitHub API.
// Prefers GitHub App auth if GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and
// GITHUB_APP_INSTALLATION_ID are all set; falls back to GITHUB_TOKEN (PAT).
func getGitHubToken() (string, error) {
	appID := os.Getenv("GITHUB_APP_ID")
	privateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	installationID := os.Getenv("GITHUB_APP_INSTALLATION_ID")

	if appID != "" && privateKey != "" && installationID != "" {
		return generateInstallationToken(appID, privateKey, installationID)
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return "", fmt.Errorf("no GitHub credentials: set GITHUB_APP_ID+GITHUB_APP_PRIVATE_KEY+GITHUB_APP_INSTALLATION_ID or GITHUB_TOKEN")
	}
	return token, nil
}

// generateInstallationToken exchanges a GitHub App private key for a short-lived
// installation access token via JWT → POST /app/installations/{id}/access_tokens.
// Uses only stdlib crypto — no heavy JWT library dependency.
func generateInstallationToken(appID, privateKeyPEM, installationID string) (string, error) {
	// 1. Parse RSA private key from PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("github app: failed to decode PEM block from private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("github app: parse private key: %w", err)
	}

	// 2. Build RS256 JWT: base64url(header).base64url(payload)
	now := time.Now().Unix()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"iat": now - 60,  // issued 60s ago to allow clock skew
		"exp": now + 600, // valid 10 minutes
		"iss": appID,
	})

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, gocrypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("github app: sign JWT: %w", err)
	}
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	// 3. POST /app/installations/{id}/access_tokens with JWT as Bearer
	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("github app: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github app: request installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("github app: installations API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("github app: parse token response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("github app: empty token in response")
	}
	return result.Token, nil
}

func (p *Plugin) HealthCheck(ctx context.Context) error {
	client, err := p.buildClient(ctx)
	if err != nil {
		return err
	}
	_, _, err = client.Organizations.Get(ctx, p.ghCfg.Org)
	return err
}

func (p *Plugin) Scan(ctx context.Context) (*plugin.ScanResult, error) {
	// Check whether any GitHub credentials are available before building client.
	// This avoids a hard error in environments where GitHub scanning is disabled.
	if os.Getenv("GITHUB_APP_ID") == "" && os.Getenv("GITHUB_TOKEN") == "" && p.ghCfg.Token == "" {
		log.Printf("github: no credentials configured (set GITHUB_APP_ID+... or GITHUB_TOKEN), skipping")
		return &plugin.ScanResult{}, nil
	}

	client, err := p.buildClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: build client: %w", err)
	}

	if p.ghCfg.Org == "" {
		return nil, fmt.Errorf("github: no org configured")
	}

	result := &plugin.ScanResult{}

	opts := &gogithub.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}

	var allRepos []*gogithub.Repository

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, p.ghCfg.Org, opts)
		if err != nil {
			wrapped := fmt.Errorf("github: ListByOrg: %w", err)
			if isCredentialError(err) {
				return nil, &plugin.AuthError{PluginName: "github", Err: wrapped}
			}
			return nil, wrapped
		}

		for _, repo := range repos {
			allRepos = append(allRepos, repo)

			agent, findings, repoRefs := p.scanRepo(ctx, client, repo, p.cfg.SeedAgents)
			if agent != nil {
				result.Agents = append(result.Agents, *agent)
			}
			result.Findings = append(result.Findings, findings...)
			result.StaticRefs = append(result.StaticRefs, repoRefs...)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// OIDC-to-agent correlation (spec §5.2 step 6) — independent of
	// name-based matching above: a deploying repo doesn't need to share a
	// name with the agent its OIDC role deploys to. Checks every Phase 1
	// seed agent's AWS-parsed trust-policy subjects against every repo this
	// scan actually found, so a stale/decommissioned trust policy
	// referencing a repo that no longer exists in the org doesn't produce
	// an edge.
	result.Edges = append(result.Edges, correlateOIDCDeployEdges(p.cfg.OrgID, p.ghCfg.Org, allRepos, p.cfg.SeedAgents)...)

	// ── Tier 2: GitHub-native agent discovery ────────────────────────────────
	// Find AI agents that exist only in GitHub repos with no AWS footprint.
	// Skip repos that already matched a seed agent from Phase 1 (AWS), since
	// those are enriched in-place above and must not produce duplicate records.
	if p.ghCfg.Tier2Discovery {
		ignore := p.loadSpecterIgnore(ctx, client)

		for _, repo := range allRepos {
			if matchSeedAgent(repo.GetName(), p.cfg.SeedAgents) != nil {
				continue // already covered by Mode 1 enrichment
			}
			if !p.shouldScanRepo(repo, ignore) {
				continue
			}

			agent, findings := p.scanRepoTier2(ctx, client, repo)
			if agent != nil {
				result.Agents = append(result.Agents, *agent)
				result.Findings = append(result.Findings, findings...)
			}
		}
	}

	return result, nil
}

// GitHubRepoContent holds scanned content from a repository.
type GitHubRepoContent struct {
	RequirementsTxt string
	PyprojectToml   string
	PackageJSON     string
	LangGraphJSON   string
	MCPJson         string
	CrewDir         bool
	ImportSignals   []string
	SecretFindings  []shared.SecretMatch
	WorkflowFiles   []workflowFile

	// Phase 11.5: intent declaration
	IntentText   string // raw text of the intent file
	IntentSource string // file name that was found
	IntentOwner  string // owner declared in intent file

	// Manifest deployment declaration (populated when .specter/manifest.yaml
	// contains a deployment.target field — a formal infrastructure declaration
	// that takes precedence over CI/Dockerfile detection).
	ManifestDeploymentTarget string // e.g. "aws_lambda", "aws_ecs", "kubernetes"
	ManifestDeploymentStatus string // e.g. "pending", "active", "deprecated"

	// Phase 11.5: source code references
	SourceRefs []types.StaticRef
}

type workflowFile struct {
	Name    string
	Content string
}

var (
	// Package manifest patterns (Signal Layer 1)
	manifestFrameworks = []struct {
		pattern    *regexp.Regexp
		framework  string
		confidence float64
		isMCP      bool
	}{
		{regexp.MustCompile(`langchain-core|langchain[>=]`), "LangChain", 0.85, false},
		{regexp.MustCompile(`langgraph[>=\s]`), "LangGraph", 0.85, false},
		{regexp.MustCompile(`crewai[>=\s]`), "CrewAI", 0.85, false},
		{regexp.MustCompile(`autogen|pyautogen|ag2[>=\s]`), "AutoGen", 0.85, false},
		{regexp.MustCompile(`openai-agents`), "OpenAI Agents", 0.85, false},
		{regexp.MustCompile(`"anthropic"|anthropic[>=]`), "Anthropic SDK", 0.75, false},
		{regexp.MustCompile(`"mcp"|^mcp[>=\s]`), "MCP SDK", 0.85, true},
		{regexp.MustCompile(`google-adk`), "Google ADK", 0.85, false},
	}
)

// scanRepo scans a single repository for agent signals and enriches the
// matching seed agent (discovered by the AWS plugin in Phase 1).
//
// If no seed agent matches the repository name, the repo is silently skipped —
// the scanner must not create standalone GITHUB-platform agent records.
// Findings and static refs are attributed to the matched seed agent's
// stableId and name so they appear on the correct agent in the platform.
func (p *Plugin) scanRepo(ctx context.Context, client *gogithub.Client, repo *gogithub.Repository, seedAgents []types.CanonicalAgentRecord) (*types.CanonicalAgentRecord, []types.FindingRecord, []types.StaticRef) {
	now := time.Now().UTC()
	repoName := repo.GetName()
	orgName := p.ghCfg.Org

	// Require a matching seed agent — no standalone GITHUB-platform records.
	seedAgent := matchSeedAgent(repoName, seedAgents)
	if seedAgent == nil {
		return nil, nil, nil
	}

	// Copy the seed agent; we will enrich this copy with GitHub-sourced data.
	// Platform, ExternalID, StableID, IAM data, etc. are preserved from AWS.
	agent := *seedAgent
	// Use the seed agent's externalID for static ref attribution.
	agentExternalID := seedAgent.ExternalID

	var findings []types.FindingRecord
	content := &GitHubRepoContent{}

	// Fetch key files
	p.fetchFileContent(ctx, client, orgName, repoName, "requirements.txt", &content.RequirementsTxt)
	p.fetchFileContent(ctx, client, orgName, repoName, "pyproject.toml", &content.PyprojectToml)
	p.fetchFileContent(ctx, client, orgName, repoName, "package.json", &content.PackageJSON)
	p.fetchFileContent(ctx, client, orgName, repoName, "langgraph.json", &content.LangGraphJSON)
	p.fetchFileContent(ctx, client, orgName, repoName, "mcp.json", &content.MCPJson)

	// Check for .crew/ directory
	_, _, crewResp, _ := client.Repositories.GetContents(ctx, orgName, repoName, ".crew", nil)
	if crewResp != nil && crewResp.StatusCode == 200 {
		content.CrewDir = true
	}

	// Phase 11.5: intent declaration (priority order per spec section 5.5)
	p.extractIntentDeclaration(ctx, client, orgName, repoName, content)

	// Phase 11.5: source code references
	p.extractSourceCodeReferences(ctx, client, orgName, repoName, agentExternalID, content)

	// Scan workflows
	p.scanWorkflows(ctx, client, orgName, repoName, content)

	// Scan for secrets
	p.scanSecretsInFiles(ctx, client, orgName, repoName, content)

	// Framework detection from manifests (Layer 1)
	allManifest := content.RequirementsTxt + "\n" + content.PyprojectToml + "\n" + content.PackageJSON
	framework, confidence, isMCP := detectFrameworkFromManifest(allManifest)

	// Layer 3: config files override
	if fw, conf, mcp := applyConfigFileOverride(content); fw != "" {
		framework, confidence, isMCP = fw, conf, mcp
	}

	if framework != "" {
		agent.Framework = framework
		agent.FrameworkConfidence = confidence
		if isMCP {
			agent.FunctionalClass = types.FunctionalClassMCPServer
		}
	}

	// Workflow findings
	for _, wf := range content.WorkflowFiles {
		wfFindings := analyzeWorkflow(wf, agent.StableID, agent.Name, now)
		findings = append(findings, wfFindings...)
	}

	// Secret findings
	for _, sf := range content.SecretFindings {
		evidence, _ := json.Marshal(map[string]string{
			"path":    sf.Path,
			"pattern": sf.Pattern,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "GITHUB_COMMITTED_SECRET",
			Severity:      "CRITICAL",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "Hardcoded secret committed to repository",
			Description:   fmt.Sprintf("Repository %s/%s contains a committed secret in %s.", orgName, repoName, sf.Path),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "github",
		})
	}

	// Only return an enriched agent if there is actually something new to add.
	// If the repo has no AI signals, no findings, and no intent declaration, the
	// seed agent from the AWS phase already has the right data — leave it alone.
	if agent.Framework == "" && len(findings) == 0 && content.IntentText == "" {
		return nil, nil, content.SourceRefs
	}

	// Phase 11.5: apply intent and alignment data.
	if content.IntentText != "" {
		agent.IntentStatement = firstSentence(content.IntentText)
		agent.IntentSource = content.IntentSource
		agent.IntentOwner = content.IntentOwner
		agent.IntentConfidence = intentConfidence(content.IntentSource)

		// Filter seed edges to only outbound edges from this agent
		var agentEdges []types.AgentEdgeRecord
		for _, e := range p.cfg.SeedEdges {
			if e.SourceStableID == agent.StableID {
				agentEdges = append(agentEdges, e)
			}
		}

		score, tier, mismatches := scoreAlignment(content.IntentText, agent, findings, agentEdges)
		agent.AlignmentScore = score
		agent.AlignmentMismatch = mismatches
		agent.AlignmentTier = tier
	} else {
		agent.AlignmentTier = "UNKNOWN"
	}

	return &agent, findings, content.SourceRefs
}

func (p *Plugin) fetchFileContent(ctx context.Context, client *gogithub.Client, org, repo, path string, dest *string) {
	fc, _, _, err := client.Repositories.GetContents(ctx, org, repo, path, nil)
	if err != nil || fc == nil {
		return
	}
	content, err := fc.GetContent()
	if err != nil {
		return
	}
	*dest = content
}

func (p *Plugin) scanWorkflows(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) {
	_, dirContents, _, err := client.Repositories.GetContents(ctx, org, repo, ".github/workflows", nil)
	if err != nil {
		return
	}
	for _, f := range dirContents {
		if f.GetType() != "file" {
			continue
		}
		var wfContent string
		p.fetchFileContent(ctx, client, org, repo, f.GetPath(), &wfContent)
		if wfContent != "" {
			content.WorkflowFiles = append(content.WorkflowFiles, workflowFile{
				Name:    f.GetName(),
				Content: wfContent,
			})
		}
	}
}

func (p *Plugin) scanSecretsInFiles(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) {
	var envContent string
	p.fetchFileContent(ctx, client, org, repo, ".env", &envContent)
	content.SecretFindings = append(content.SecretFindings, shared.ScanContentForSecrets(".env", envContent)...)

	// Also check requirements.txt for accidentally committed secrets
	for _, item := range []struct{ path, text string }{
		{path: "requirements.txt", text: content.RequirementsTxt},
		{path: "pyproject.toml", text: content.PyprojectToml},
	} {
		content.SecretFindings = append(content.SecretFindings, shared.ScanContentForSecrets(item.path, item.text)...)
	}
}

func analyzeWorkflow(wf workflowFile, agentStableID, agentName string, now time.Time) []types.FindingRecord {
	var findings []types.FindingRecord
	content := wf.Content

	if strings.Contains(content, "aws-access-key-id") {
		evidence, _ := json.Marshal(map[string]string{
			"workflow": wf.Name,
			"signal":   "aws-access-key-id",
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "GITHUB_STATIC_AWS_CREDS",
			Severity:      "HIGH",
			AgentStableID: agentStableID,
			AgentName:     agentName,
			Title:         "Workflow uses static AWS credentials",
			Description:   fmt.Sprintf("Workflow %s uses aws-access-key-id (static credentials) instead of OIDC.", wf.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "github",
		})
	}

	if strings.Contains(content, "id-token: write") && !strings.Contains(content, "role-to-assume") {
		evidence, _ := json.Marshal(map[string]string{
			"workflow": wf.Name,
			"signal":   "id-token: write without role-to-assume",
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "GITHUB_UNSCOPED_WORKFLOW",
			Severity:      "MEDIUM",
			AgentStableID: agentStableID,
			AgentName:     agentName,
			Title:         "Workflow requests OIDC token without assuming a role",
			Description:   fmt.Sprintf("Workflow %s requests id-token: write permission but does not specify role-to-assume.", wf.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "github",
		})
	}

	return findings
}

// applyConfigFileOverride returns the framework, confidence, and isMCP that a
// Layer 3 config-file signal implies, given content already fetched for a
// repo. A recognised config file (langgraph.json, .crew/, mcp.json) is a
// stronger, more direct signal than a manifest dependency line, so it always
// overrides Layer 1's detectFrameworkFromManifest result when present.
// Returns ("", 0, false) when no config file was found — callers keep
// whatever Layer 1 already determined.
func applyConfigFileOverride(content *GitHubRepoContent) (framework string, confidence float64, isMCP bool) {
	switch {
	case content.LangGraphJSON != "":
		return "LangGraph", 0.97, false
	case content.CrewDir:
		return "CrewAI", 0.95, false
	case content.MCPJson != "":
		return "MCP SDK", 0.98, true
	default:
		return "", 0, false
	}
}

func detectFrameworkFromManifest(content string) (framework string, confidence float64, isMCP bool) {
	for _, mf := range manifestFrameworks {
		if mf.pattern.MatchString(content) {
			if mf.confidence > confidence {
				framework = mf.framework
				confidence = mf.confidence
				isMCP = mf.isMCP
			}
		}
	}
	return
}

// ── Phase 11.5: intent declaration ──────────────────────────────────────────

// IntentSource constants — canonical values used in IntentSource field.
const (
	IntentSourceManifest = "MANIFEST"
	IntentSourceAgentMD  = "AGENT_MD"
	IntentSourceClaudeMD = "CLAUDE_MD"
	IntentSourceReadme   = "README"
)

// extractIntentDeclaration looks for intent files in priority order:
// .specter/manifest.yaml → AGENT.md → CLAUDE.md → README.md
func (p *Plugin) extractIntentDeclaration(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) {
	// Priority 1: .specter/manifest.yaml — nested specter.agent.intent schema.
	// Parsing lives in internal/plugin/shared so the AWS plugin's CodeCommit
	// discovery parses the exact same manifest format identically.
	var manifestTxt string
	p.fetchFileContent(ctx, client, org, repo, ".specter/manifest.yaml", &manifestTxt)
	if manifestTxt != "" {
		if m, ok := shared.ParseSpecterManifest(manifestTxt); ok {
			if m.Intent != "" {
				content.IntentText = truncate(m.Intent, 500)
				content.IntentSource = IntentSourceManifest
				content.IntentOwner = m.Owner
			}
			// Capture deployment declaration regardless of whether intent was found.
			// A deployment.target is a formal governance statement even when
			// status is "pending" and even when the manifest has no intent field.
			if m.DeploymentTarget != "" {
				content.ManifestDeploymentTarget = m.DeploymentTarget
				content.ManifestDeploymentStatus = m.DeploymentStatus
			}
			if m.Intent != "" {
				return
			}
		}
	}

	// Priority 2: AGENT.md
	var agentMD string
	p.fetchFileContent(ctx, client, org, repo, "AGENT.md", &agentMD)
	if agentMD != "" {
		content.IntentText = extractMarkdownIntent(agentMD)
		content.IntentSource = IntentSourceAgentMD
		content.IntentOwner = extractOwnerFromMarkdown(agentMD)
		return
	}

	// Priority 3: CLAUDE.md
	var claudeMD string
	p.fetchFileContent(ctx, client, org, repo, "CLAUDE.md", &claudeMD)
	if claudeMD != "" {
		content.IntentText = extractMarkdownIntent(claudeMD)
		content.IntentSource = IntentSourceClaudeMD
		content.IntentOwner = extractOwnerFromMarkdown(claudeMD)
		return
	}

	// Priority 4: README.md — only use if it has at least 50 words (substantive)
	var readmeMD string
	p.fetchFileContent(ctx, client, org, repo, "README.md", &readmeMD)
	if readmeMD != "" && wordCount(readmeMD) >= 50 {
		content.IntentText = extractMarkdownIntent(readmeMD)
		content.IntentSource = IntentSourceReadme
		content.IntentOwner = extractOwnerFromMarkdown(readmeMD)
	}
}

// extractMarkdownIntent extracts the most relevant intent paragraph from a
// markdown document, capped at 500 characters.
//
// Search order:
//  1. First non-empty paragraph under a recognised intent heading
//     (## Purpose, ## Overview, ## What this agent does, ## About)
//  2. First non-empty paragraph after the H1 title
//  3. First substantive non-heading paragraph anywhere in the document
func extractMarkdownIntent(text string) string {
	lines := strings.Split(text, "\n")
	intentHeadings := map[string]bool{
		"## purpose":              true,
		"## overview":             true,
		"## what this agent does": true,
		"## about":                true,
		"## description":          true,
	}

	// Pass 1: look for content under a recognised intent heading
	for i, line := range lines {
		norm := strings.ToLower(strings.TrimSpace(line))
		if intentHeadings[norm] {
			para := firstSubstantiveParagraph(lines[i+1:])
			if para != "" {
				return truncate(para, 500)
			}
		}
	}

	// Pass 2: first paragraph after the H1 title
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") && !strings.HasPrefix(trimmed, "## ") {
			para := firstSubstantiveParagraph(lines[i+1:])
			if para != "" {
				return truncate(para, 500)
			}
		}
	}

	// Pass 3: first substantive paragraph anywhere
	para := firstSubstantiveParagraph(lines)
	return truncate(para, 500)
}

// firstSubstantiveParagraph returns the first paragraph from lines that has
// at least 10 characters and is not a markdown heading or horizontal rule.
func firstSubstantiveParagraph(lines []string) string {
	var buf []string
	inParagraph := false

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		isHeading := strings.HasPrefix(line, "#")
		isRule := strings.HasPrefix(line, "---") || strings.HasPrefix(line, "===")
		isCode := strings.HasPrefix(line, "```") || strings.HasPrefix(line, "    ")
		isBadge := strings.Contains(line, "[![") || strings.Contains(line, "![")

		if line == "" {
			if inParagraph && len(buf) > 0 {
				break // end of paragraph
			}
			continue
		}
		if isHeading || isRule || isCode || isBadge {
			if inParagraph {
				break
			}
			continue
		}
		// Strip markdown markup for cleaner text
		cleaned := stripMarkdown(line)
		if len(cleaned) < 5 {
			continue
		}
		buf = append(buf, cleaned)
		inParagraph = true
	}

	result := strings.Join(buf, " ")
	if len(result) < 10 {
		return ""
	}
	return result
}

// stripMarkdown removes inline markdown from a line (bold, italic, links, code).
var reMarkdownStrip = regexp.MustCompile(`\[([^\]]+)\]\([^\)]+\)|[*_` + "`" + `]`)

func stripMarkdown(line string) string {
	// Replace [text](url) links with just the text
	line = regexp.MustCompile(`\[([^\]]+)\]\([^\)]+\)`).ReplaceAllString(line, "$1")
	// Remove remaining markdown punctuation
	line = regexp.MustCompile(`[*_`+"`"+`]`).ReplaceAllString(line, "")
	return strings.TrimSpace(line)
}

// extractOwnerFromMarkdown looks for ownership signals in markdown text:
//  1. "Owner:", "Maintainer:", "Contact:" label on a line
//  2. Email addresses near "maintained by", "owned by", "contact" keywords
func extractOwnerFromMarkdown(text string) string {
	// Pattern 1: labelled field
	labelPat := regexp.MustCompile(`(?im)^(?:Owner|Maintainer|Contact|Owned by|Maintained by):\s*(.+)$`)
	if m := labelPat.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}

	// Pattern 2: email near ownership keywords
	emailPat := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	ownershipPat := regexp.MustCompile(`(?i)(maintained by|owned by|contact|owner|maintainer)`)

	lower := strings.ToLower(text)
	for _, line := range strings.Split(lower, "\n") {
		if ownershipPat.MatchString(line) {
			// Find an email in the original-case line at the same position
			for _, rawLine := range strings.Split(text, "\n") {
				if strings.EqualFold(strings.TrimSpace(rawLine), strings.TrimSpace(line)) {
					if email := emailPat.FindString(rawLine); email != "" {
						return email
					}
				}
			}
		}
	}

	return ""
}

// intentConfidence maps the intent source to a confidence score.
func intentConfidence(source string) float64 {
	switch source {
	case IntentSourceManifest:
		return 0.98
	case IntentSourceAgentMD:
		return 0.90
	case IntentSourceClaudeMD:
		return 0.85
	case IntentSourceReadme:
		return 0.60 // README may describe the repo, not just the agent
	}
	return 0.50
}

// firstSentence extracts the first meaningful sentence from a block of text,
// stripping markdown headers and empty lines.
func firstSentence(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "---") {
			continue
		}
		line = stripMarkdown(line)
		line = strings.TrimSpace(line)
		if len(line) < 10 {
			continue
		}
		if idx := strings.IndexAny(line, ".!?"); idx > 0 {
			return line[:idx+1]
		}
		return line
	}
	return strings.TrimSpace(text)
}

// ── Phase 11.5: alignment scoring ──────────────────────────────────────────

// scoreAlignment computes how well an agent's stated intent matches its observed
// behaviour. Returns a score (0.0–1.0), a tier string, and a slice of mismatches.
//
// Signals checked:
//  1. "read-only", "analytics", "reporting" in intent → penalise if IAM has
//     write/delete/put actions or wildcard resource permissions.
//  2. "standalone", "independent" in intent → penalise if outbound A2A_CALL
//     or STATIC_REF edges exist (agent delegates to other agents).
//  3. "worker", "subprocess" in intent → penalise if IAM grants ecs:RunTask
//     or lambda:InvokeFunction (worker that can spawn tasks is an orchestrator).
//
// agentEdges must be pre-filtered to only the edges whose SourceStableID
// matches the agent being scored (outbound edges only).
func scoreAlignment(
	intentText string,
	agent types.CanonicalAgentRecord,
	findings []types.FindingRecord,
	agentEdges []types.AgentEdgeRecord,
) (score float64, tier string, mismatches []string) {
	if intentText == "" {
		return 0.0, "UNKNOWN", nil
	}

	score = 1.0
	lower := strings.ToLower(intentText)

	// Build finding rule set for quick lookup
	findingRules := map[string]bool{}
	for _, f := range findings {
		findingRules[f.RuleID] = true
	}

	// ── Signal 1: read-only / analytics intent vs write IAM permissions ──────
	if containsAny(lower, "read-only", "readonly", "analytics", "reporting", "read only", "view only", "monitoring", "indexing") {
		wroteIAMMismatch := false
		for _, perm := range agent.IAMPermissions {
			raw := strings.ToLower(perm.RawAction)
			if strings.Contains(raw, "put") || strings.Contains(raw, "delete") ||
				strings.Contains(raw, "write") || strings.Contains(raw, "create") ||
				strings.Contains(raw, "update") {
				score -= 0.30
				mismatches = append(mismatches, fmt.Sprintf(
					"intent claims read-only/analytics role but IAM grants write action %s", perm.RawAction))
				wroteIAMMismatch = true
				break
			}
		}
		if !wroteIAMMismatch && agent.HasWildcard {
			score -= 0.20
			mismatches = append(mismatches, "intent claims read-only/analytics scope but IAM role has wildcard resource permissions")
		}
	}

	// ── Signal 2: standalone / independent intent vs outbound delegation edges ─
	if containsAny(lower, "standalone", "independent", "self-contained", "no external") {
		for _, e := range agentEdges {
			if e.EdgeType == types.EdgeTypeA2ACall || e.EdgeType == types.EdgeTypeStaticRef {
				score -= 0.25
				mismatches = append(mismatches, fmt.Sprintf(
					"intent claims standalone/independent but agent has outbound %s edge to %s",
					e.EdgeType, e.TargetStableID))
				break
			}
		}
	}

	// ── Signal 3: worker intent vs orchestration IAM permissions ─────────────
	if containsAny(lower, "worker", "subprocess", "sub-agent", "leaf") {
		for _, perm := range agent.IAMPermissions {
			raw := strings.ToLower(perm.RawAction)
			if raw == "ecs:runtask" || raw == "lambda:invokefunction" {
				score -= 0.25
				mismatches = append(mismatches, fmt.Sprintf(
					"intent claims worker role but IAM grants orchestration action %s", perm.RawAction))
				break
			}
		}
	}

	// ── Carry-over: security claims vs unauthenticated findings ───────────────
	if containsAny(lower, "secure", "authenticated", "private", "internal only", "authorized") {
		if findingRules["A2A_AUTH_NONE"] || findingRules["LAMBDA_PUBLIC_URL_NO_AUTH"] {
			score -= 0.20
			mismatches = append(mismatches, "intent claims authenticated access but agent has unauthenticated public endpoints")
		}
	}

	// ── Carry-over: committed secret vs any stated security posture ───────────
	if findingRules["GITHUB_COMMITTED_SECRET"] {
		score -= 0.15
		mismatches = append(mismatches, "secret committed to repository undermines stated security posture")
	}

	if score < 0.0 {
		score = 0.0
	}

	switch {
	case score >= 0.80:
		tier = "ALIGNED"
	case score >= 0.60:
		tier = "PARTIAL"
	default:
		tier = "MISMATCHED"
	}
	return
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ── Phase 11.5: source code reference extraction ────────────────────────────

var (
	srcLambdaARN   = regexp.MustCompile(`arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[a-zA-Z0-9_:-]+`)
	srcAPIGWARN    = regexp.MustCompile(`arn:aws:execute-api:[a-z0-9-]+:\d{12}:[a-zA-Z0-9]+`)
	srcAPIGWURL    = regexp.MustCompile(`https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:/[^\s"']*)?`)
	srcBedrockARN  = regexp.MustCompile(`arn:aws:bedrock:[a-z0-9-]+:\d{12}:(?:agent|foundation-model|agent-alias)/[a-zA-Z0-9/_.-]+`)
	srcFunctionURL = regexp.MustCompile(`https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws(?:/[^\s"']*)?`)
)

// isTestOrVendorPath returns true if the path looks like a test or vendored file.
func isTestOrVendorPath(path string) bool {
	lower := strings.ToLower(path)
	testDirs := []string{"test/", "tests/", "__tests__/", "vendor/", "node_modules/", ".tox/", "venv/", "spec/"}
	for _, dir := range testDirs {
		if strings.HasPrefix(lower, dir) || strings.Contains(lower, "/"+dir) {
			return true
		}
	}
	testFiles := []string{"_test.py", "_test.go", "test_.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"}
	for _, suf := range testFiles {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

// sourceCodePatterns are the ARN/URL patterns that imply an inter-agent dependency.
type sourceCodePattern struct {
	re       *regexp.Regexp
	edgeType types.EdgeType
}

var sourceCodePatterns = []sourceCodePattern{
	{srcLambdaARN, types.EdgeTypeStaticRef},
	{srcAPIGWARN, types.EdgeTypeStaticRef},
	{srcAPIGWURL, types.EdgeTypeStaticRef},
	{srcBedrockARN, types.EdgeTypeStaticRef},
	{srcFunctionURL, types.EdgeTypeStaticRef},
}

// extractSourceCodeReferences scans common source files in the repo for
// hard-coded references to other agents or services.
// Test files and vendor directories are skipped per spec section 5.5.
func (p *Plugin) extractSourceCodeReferences(ctx context.Context, client *gogithub.Client, org, repo, agentExternalID string, content *GitHubRepoContent) {
	// Scan a curated set of likely agent entry-point files
	candidateFiles := []string{
		"main.py", "agent.py", "handler.py", "app.py", "run.py",
		"index.ts", "index.js", "main.ts", "main.js",
		"agent.ts", "agent.js", "handler.ts", "handler.js",
		"src/main.py", "src/agent.py", "src/handler.py",
		"src/index.ts", "src/index.js",
	}

	seen := map[string]bool{}
	for _, filePath := range candidateFiles {
		if isTestOrVendorPath(filePath) {
			continue
		}
		var fileContent string
		p.fetchFileContent(ctx, client, org, repo, filePath, &fileContent)
		if fileContent == "" {
			continue
		}

		for _, pat := range sourceCodePatterns {
			matches := pat.re.FindAllString(fileContent, -1)
			for _, match := range matches {
				if seen[match] {
					continue
				}
				seen[match] = true
				content.SourceRefs = append(content.SourceRefs, types.StaticRef{
					SourceAgentExternalID: agentExternalID,
					TargetExternalID:      match,
					RefSource:             "SOURCE_CODE",
					EdgeType:              pat.edgeType,
					Confidence:            0.70,
					Evidence:              fmt.Sprintf("hardcoded reference in %s/%s:%s", org, repo, filePath),
				})
			}
		}
	}
}

// wordCount returns the approximate number of words in a string.
func wordCount(s string) int {
	count := 0
	inWord := false
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			inWord = false
		} else if !inWord {
			count++
			inWord = true
		}
	}
	return count
}

// stableID computes a stable cross-scan identifier.
func stableID(orgID, externalID string) string {
	h := sha256.Sum256([]byte(orgID + "|" + externalID))
	return hex.EncodeToString(h[:])[:16]
}

// normalizeName returns a lowercase, alphanumeric-only version of s, suitable
// for fuzzy name matching between repo names and agent names.
func normalizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// matchSeedAgent finds the seed agent that corresponds to repoName.
//
// Matching strategy (in priority order):
//  1. Exact normalized match: normalizeName(agent.Name) == normalizeName(repoName)
//  2. Prefix match: agent name starts with the repo name (handles
//     "CustomerInsight-Orchestrator" vs repo "customer-insight").
//
// Returns nil if no seed agent matches — the repo should be skipped entirely.
func matchSeedAgent(repoName string, seedAgents []types.CanonicalAgentRecord) *types.CanonicalAgentRecord {
	if len(seedAgents) == 0 {
		return nil
	}
	repoNorm := normalizeName(repoName)

	// Pass 1: exact normalized match.
	for i := range seedAgents {
		if normalizeName(seedAgents[i].Name) == repoNorm {
			return &seedAgents[i]
		}
	}

	// Pass 2: seed agent normalized name starts with repo normalized name.
	// Minimum 5 chars to avoid spurious short-prefix matches.
	if len(repoNorm) >= 5 {
		for i := range seedAgents {
			seedNorm := normalizeName(seedAgents[i].Name)
			if strings.HasPrefix(seedNorm, repoNorm) {
				return &seedAgents[i]
			}
		}
	}

	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
