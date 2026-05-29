// Package github implements the GitHub scanner plugin.
// It scans repositories in a GitHub organization for agent code,
// committed secrets, and workflow credential hygiene.
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode"

	gogithub "github.com/google/go-github/v66/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// GitHubPluginConfig holds GitHub-specific configuration.
type GitHubPluginConfig struct {
	Token      string `json:"token"`
	Org        string `json:"org"`
	AppID      int64  `json:"appId"`
	PrivateKey string `json:"privateKey"`
}

// Plugin is the GitHub scanner plugin.
type Plugin struct {
	cfg   plugin.PluginConfig
	ghCfg GitHubPluginConfig
}

func init() {
	plugin.Register(&Plugin{})
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
	if p.ghCfg.Token == "" {
		return nil, fmt.Errorf("github: no token configured (set GITHUB_TOKEN)")
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: p.ghCfg.Token})
	tc := oauth2.NewClient(ctx, ts)
	return gogithub.NewClient(tc), nil
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
	if p.ghCfg.Token == "" {
		log.Printf("github: GITHUB_TOKEN not set, skipping GitHub scan")
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

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, p.ghCfg.Org, opts)
		if err != nil {
			return nil, fmt.Errorf("github: ListByOrg: %w", err)
		}

		for _, repo := range repos {
			agent, findings, repoRefs := p.scanRepo(ctx, client, repo)
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
	SecretFindings  []secretFinding
	WorkflowFiles   []workflowFile

	// Phase 11.5: intent declaration
	IntentText   string // raw text of the intent file
	IntentSource string // file name that was found
	IntentOwner  string // owner declared in intent file

	// Phase 11.5: source code references
	SourceRefs []types.StaticRef
}

type secretFinding struct {
	Path    string
	Pattern string
	Match   string
}

type workflowFile struct {
	Name    string
	Content string
}

var (
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`sk-svcacct-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`sk-ant-api0[3-9]-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}

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

func (p *Plugin) scanRepo(ctx context.Context, client *gogithub.Client, repo *gogithub.Repository) (*types.CanonicalAgentRecord, []types.FindingRecord, []types.StaticRef) {
	now := time.Now().UTC()
	repoName := repo.GetName()
	orgName := p.ghCfg.Org

	agentExternalID := fmt.Sprintf("github:%s/%s", orgName, repoName)
	agent := &types.CanonicalAgentRecord{
		Name:             orgName + "/" + repoName,
		Platform:         "GITHUB",
		ExternalID:       agentExternalID,
		StableID:         stableID(p.cfg.OrgID, agentExternalID),
		OrgID:            p.cfg.OrgID,
		LastSeenAt:       now,
		VisibilitySource: "SCANNER",
	}

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
	if content.LangGraphJSON != "" {
		framework = "LangGraph"
		confidence = 0.97
		isMCP = false
	} else if content.CrewDir {
		framework = "CrewAI"
		confidence = 0.95
		isMCP = false
	} else if content.MCPJson != "" {
		framework = "MCP SDK"
		confidence = 0.98
		isMCP = true
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

	// Only return agent if it looks like an AI agent repo
	if agent.Framework == "" && len(findings) == 0 && content.IntentText == "" {
		return nil, nil, nil
	}

	// Phase 11.5: apply intent and alignment data
	if content.IntentText != "" {
		agent.IntentStatement = firstSentence(content.IntentText)
		agent.IntentSource = content.IntentSource
		agent.IntentOwner = content.IntentOwner
		agent.IntentConfidence = intentConfidence(content.IntentSource)

		score, mismatches := scoreAlignment(*agent, findings, content.IntentText)
		agent.AlignmentScore = score
		agent.AlignmentMismatch = mismatches
		agent.AlignmentTier = alignmentTier(score)
	} else {
		agent.AlignmentTier = "UNKNOWN"
	}

	return agent, findings, content.SourceRefs
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
	if envContent != "" {
		for _, pat := range secretPatterns {
			if m := pat.FindString(envContent); m != "" {
				content.SecretFindings = append(content.SecretFindings, secretFinding{
					Path:    ".env",
					Pattern: truncate(pat.String(), 20),
					Match:   truncate(m, 20),
				})
			}
		}
	}

	// Also check requirements.txt for accidentally committed secrets
	for _, item := range []struct{ path, text string }{
		{path: "requirements.txt", text: content.RequirementsTxt},
		{path: "pyproject.toml", text: content.PyprojectToml},
	} {
		if item.text == "" {
			continue
		}
		for _, pat := range secretPatterns {
			if m := pat.FindString(item.text); m != "" {
				content.SecretFindings = append(content.SecretFindings, secretFinding{
					Path:    item.path,
					Pattern: truncate(pat.String(), 20),
					Match:   truncate(m, 20),
				})
			}
		}
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

// specterManifest is a partial parse of .specter/manifest.yaml.
type specterManifest struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Owner       string `yaml:"owner"`
}

// extractIntentDeclaration looks for intent files in priority order:
// .specter/manifest.yaml → AGENT.md → CLAUDE.md → README.md
func (p *Plugin) extractIntentDeclaration(ctx context.Context, client *gogithub.Client, org, repo string, content *GitHubRepoContent) {
	// Priority 1: .specter/manifest.yaml
	var manifestTxt string
	p.fetchFileContent(ctx, client, org, repo, ".specter/manifest.yaml", &manifestTxt)
	if manifestTxt != "" {
		var m specterManifest
		if err := yaml.Unmarshal([]byte(manifestTxt), &m); err == nil && m.Description != "" {
			content.IntentText = m.Description
			content.IntentSource = ".specter/manifest.yaml"
			content.IntentOwner = m.Owner
			return
		}
	}

	// Priority 2: AGENT.md
	var agentMD string
	p.fetchFileContent(ctx, client, org, repo, "AGENT.md", &agentMD)
	if agentMD != "" {
		content.IntentText = agentMD
		content.IntentSource = "AGENT.md"
		content.IntentOwner = extractOwnerFromMarkdown(agentMD)
		return
	}

	// Priority 3: CLAUDE.md
	var claudeMD string
	p.fetchFileContent(ctx, client, org, repo, "CLAUDE.md", &claudeMD)
	if claudeMD != "" {
		content.IntentText = claudeMD
		content.IntentSource = "CLAUDE.md"
		content.IntentOwner = extractOwnerFromMarkdown(claudeMD)
		return
	}

	// Priority 4: README.md
	var readmeMD string
	p.fetchFileContent(ctx, client, org, repo, "README.md", &readmeMD)
	if readmeMD != "" {
		content.IntentText = readmeMD
		content.IntentSource = "README.md"
		content.IntentOwner = extractOwnerFromMarkdown(readmeMD)
	}
}

// extractOwnerFromMarkdown looks for "Owner:" or "Maintainer:" declarations.
func extractOwnerFromMarkdown(text string) string {
	ownerPat := regexp.MustCompile(`(?im)^(?:Owner|Maintainer|Contact):\s*(.+)$`)
	if m := ownerPat.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// intentConfidence maps the intent source to a confidence score.
func intentConfidence(source string) float64 {
	switch source {
	case ".specter/manifest.yaml":
		return 0.98
	case "AGENT.md":
		return 0.90
	case "CLAUDE.md":
		return 0.85
	case "README.md":
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
		// Strip markdown bold/italic/inline code markers
		line = regexp.MustCompile(`[*_` + "`" + `]`).ReplaceAllString(line, "")
		line = strings.TrimSpace(line)
		if len(line) < 10 {
			continue
		}
		// Trim to the first sentence (end at . ! ?)
		if idx := strings.IndexAny(line, ".!?"); idx > 0 {
			return line[:idx+1]
		}
		return line
	}
	return strings.TrimSpace(text)
}

// ── Phase 11.5: alignment scoring ──────────────────────────────────────────

// scoreAlignment computes how well an agent's stated intent matches its observed
// behaviour. Returns a score (0.0–1.0) and a slice of specific mismatches found.
func scoreAlignment(agent types.CanonicalAgentRecord, findings []types.FindingRecord, intentText string) (float64, []string) {
	score := 1.0
	var mismatches []string
	lower := strings.ToLower(intentText)

	// Build a set of finding rule IDs for quick lookup
	findingRules := map[string]bool{}
	for _, f := range findings {
		findingRules[f.RuleID] = true
	}

	// Intent claims security/auth but agent has no-auth endpoints
	if containsAny(lower, "secure", "authenticated", "private", "internal only", "authorized") {
		if findingRules["A2A_AUTH_NONE"] || findingRules["LAMBDA_PUBLIC_URL_NO_AUTH"] {
			score -= 0.35
			mismatches = append(mismatches, "intent claims authenticated access but agent has unauthenticated public endpoints")
		}
		if findingRules["GITHUB_STATIC_AWS_CREDS"] {
			score -= 0.15
			mismatches = append(mismatches, "intent claims secure operation but workflow uses static credentials")
		}
	}

	// Intent claims read-only but agent has write/mutation permissions
	if containsAny(lower, "read-only", "readonly", "read only", "view only", "non-destructive") {
		for _, perm := range agent.IAMPermissions {
			if perm.RawAction == "s3:PutObject" || perm.RawAction == "s3:DeleteObject" ||
				strings.Contains(strings.ToLower(perm.RawAction), "put") ||
				strings.Contains(strings.ToLower(perm.RawAction), "write") ||
				strings.Contains(strings.ToLower(perm.RawAction), "delete") {
				score -= 0.25
				mismatches = append(mismatches, fmt.Sprintf("intent claims read-only but IAM grants %s", perm.RawAction))
				break
			}
		}
	}

	// Intent claims narrow scope but agent has wildcard permissions
	if agent.HasWildcard && containsAny(lower, "limited", "scoped", "least privilege", "narrow") {
		score -= 0.20
		mismatches = append(mismatches, "intent claims limited scope but IAM role has wildcard resource permissions")
	}

	// Intent claims internal/private but agent has committed secrets
	if findingRules["GITHUB_COMMITTED_SECRET"] {
		score -= 0.20
		mismatches = append(mismatches, "secret committed to repository undermines stated security posture")
	}

	// Intent mentions orchestration but functional class is WORKER
	if containsAny(lower, "orchestrat", "coordinate", "delegates to", "manages agents") &&
		agent.FunctionalClass == types.FunctionalClassWorker {
		score -= 0.15
		mismatches = append(mismatches, "intent claims orchestration role but agent is classified as WORKER")
	}

	if score < 0.0 {
		score = 0.0
	}
	return score, mismatches
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// alignmentTier maps a score to a tier label.
func alignmentTier(score float64) string {
	switch {
	case score >= 0.80:
		return "ALIGNED"
	case score >= 0.60:
		return "PARTIAL"
	case score > 0.0:
		return "MISMATCHED"
	default:
		return "MISMATCHED"
	}
}

// ── Phase 11.5: source code reference extraction ────────────────────────────

var (
	srcLambdaARN    = regexp.MustCompile(`arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[a-zA-Z0-9_:-]+`)
	srcAPIGWARN     = regexp.MustCompile(`arn:aws:execute-api:[a-z0-9-]+:\d{12}:[a-zA-Z0-9]+`)
	srcAPIGWURL     = regexp.MustCompile(`https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:/[^\s"']*)?`)
	srcBedrockARN   = regexp.MustCompile(`arn:aws:bedrock:[a-z0-9-]+:\d{12}:(?:agent|foundation-model|agent-alias)/[a-zA-Z0-9/_.-]+`)
	srcFunctionURL  = regexp.MustCompile(`https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws(?:/[^\s"']*)?`)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
