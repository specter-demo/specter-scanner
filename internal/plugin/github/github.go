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

	gogithub "github.com/google/go-github/v66/github"
	"golang.org/x/oauth2"

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
			agent, findings := p.scanRepo(ctx, client, repo)
			if agent != nil {
				result.Agents = append(result.Agents, *agent)
			}
			result.Findings = append(result.Findings, findings...)
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

func (p *Plugin) scanRepo(ctx context.Context, client *gogithub.Client, repo *gogithub.Repository) (*types.CanonicalAgentRecord, []types.FindingRecord) {
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
	if agent.Framework == "" && len(findings) == 0 {
		return nil, nil
	}

	return agent, findings
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
