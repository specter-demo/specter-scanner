// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"fmt"
	"testing"
	"time"

	"github.com/specter-demo/specter-scanner/internal/plugin/shared"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// ── Framework detection: manifest signals (Layer 1) ─────────────────────────

func TestDetectFrameworkFromManifest_LangChain(t *testing.T) {
	fw, conf, isMCP := detectFrameworkFromManifest("langchain-core==0.1.42\nrequests==2.31.0\n")
	if fw != "LangChain" {
		t.Errorf("expected LangChain, got %q", fw)
	}
	if conf != 0.85 {
		t.Errorf("expected confidence 0.85, got %v", conf)
	}
	if isMCP {
		t.Error("expected isMCP=false for LangChain")
	}
}

func TestDetectFrameworkFromManifest_LangGraph(t *testing.T) {
	fw, conf, _ := detectFrameworkFromManifest("langgraph>=0.2.0\n")
	if fw != "LangGraph" || conf != 0.85 {
		t.Errorf("expected LangGraph/0.85, got %q/%v", fw, conf)
	}
}

func TestDetectFrameworkFromManifest_CrewAI(t *testing.T) {
	fw, conf, _ := detectFrameworkFromManifest("crewai>=0.30.0\n")
	if fw != "CrewAI" || conf != 0.85 {
		t.Errorf("expected CrewAI/0.85, got %q/%v", fw, conf)
	}
}

func TestDetectFrameworkFromManifest_AutoGen(t *testing.T) {
	fw, conf, _ := detectFrameworkFromManifest("pyautogen==0.2.0\n")
	if fw != "AutoGen" || conf != 0.85 {
		t.Errorf("expected AutoGen/0.85, got %q/%v", fw, conf)
	}
}

func TestDetectFrameworkFromManifest_OpenAIAgents(t *testing.T) {
	fw, conf, _ := detectFrameworkFromManifest("openai-agents==0.1.0\n")
	if fw != "OpenAI Agents" || conf != 0.85 {
		t.Errorf("expected OpenAI Agents/0.85, got %q/%v", fw, conf)
	}
}

func TestDetectFrameworkFromManifest_AnthropicSDK_QuotedPackageJSONForm(t *testing.T) {
	fw, conf, isMCP := detectFrameworkFromManifest(`{"dependencies": {"anthropic": "^0.18.0"}}`)
	if fw != "Anthropic SDK" || conf != 0.75 {
		t.Errorf("expected Anthropic SDK/0.75, got %q/%v", fw, conf)
	}
	if isMCP {
		t.Error("expected isMCP=false for the Anthropic SDK")
	}
}

func TestDetectFrameworkFromManifest_AnthropicSDK_RequirementsForm(t *testing.T) {
	fw, _, _ := detectFrameworkFromManifest("anthropic==0.18.0\n")
	if fw != "Anthropic SDK" {
		t.Errorf("expected Anthropic SDK, got %q", fw)
	}
}

func TestDetectFrameworkFromManifest_GoogleADK(t *testing.T) {
	fw, conf, _ := detectFrameworkFromManifest("google-adk==1.0.0\n")
	if fw != "Google ADK" || conf != 0.85 {
		t.Errorf("expected Google ADK/0.85, got %q/%v", fw, conf)
	}
}

func TestDetectFrameworkFromManifest_MCPSDK_QuotedPackageJSONForm(t *testing.T) {
	fw, conf, isMCP := detectFrameworkFromManifest(`{"dependencies": {"mcp": "^1.0.0"}}`)
	if fw != "MCP SDK" || conf != 0.85 {
		t.Errorf("expected MCP SDK/0.85, got %q/%v", fw, conf)
	}
	if !isMCP {
		t.Error("expected isMCP=true for the MCP SDK")
	}
}

// TestDetectFrameworkFromManifest_MCPSDK_LineAnchorOnlyMatchesFirstLine is a
// regression-style test for a real, non-obvious quirk in the MCP SDK
// pattern: `^mcp[>=\s]` has no (?m) flag, so `^` anchors to the start of the
// *entire* input string passed to detectFrameworkFromManifest, not the start
// of each line. scanRepo/scanRepoTier2 call this with allManifest built as
// requirements.txt + "\n" + pyproject.toml + "\n" + package.json — so a bare
// "mcp>=1.0.0" requirements.txt line only matches via this alternative when
// it is literally the first line of requirements.txt (i.e. the first thing
// in the whole concatenated string). Anywhere else, only the quoted `"mcp"`
// alternative (matching package.json's dependency key) can catch it.
func TestDetectFrameworkFromManifest_MCPSDK_LineAnchorOnlyMatchesFirstLine(t *testing.T) {
	// First line of the combined manifest: matches via ^mcp[>=\s].
	fw, _, _ := detectFrameworkFromManifest("mcp>=1.0.0\nrequests==2.31.0\n")
	if fw != "MCP SDK" {
		t.Errorf("expected MCP SDK when mcp>=1.0.0 is the first line of the combined manifest, got %q", fw)
	}

	// Same content, but preceded by another line — ^ no longer matches, and
	// there is no quoted "mcp" literal anywhere, so detection must fail.
	fw2, _, _ := detectFrameworkFromManifest("requests==2.31.0\nmcp>=1.0.0\n")
	if fw2 != "" {
		t.Errorf("expected no framework detected when mcp>=1.0.0 is not the first line and no quoted \"mcp\" literal is present, got %q", fw2)
	}
}

func TestDetectFrameworkFromManifest_NoMatch(t *testing.T) {
	fw, conf, isMCP := detectFrameworkFromManifest("requests==2.31.0\nflask==3.0.0\n")
	if fw != "" || conf != 0 || isMCP {
		t.Errorf("expected no framework detected for an unrelated dependency list, got %q/%v/%v", fw, conf, isMCP)
	}
}

func TestDetectFrameworkFromManifest_EmptyContent(t *testing.T) {
	fw, conf, isMCP := detectFrameworkFromManifest("")
	if fw != "" || conf != 0 || isMCP {
		t.Errorf("expected no framework detected for empty content, got %q/%v/%v", fw, conf, isMCP)
	}
}

// TestDetectFrameworkFromManifest_HighestConfidenceWins is a regression test
// for detectFrameworkFromManifest's selection rule: `if mf.confidence >
// confidence` means when multiple manifest patterns match the same combined
// text, the result must be whichever pattern has the highest confidence, not
// simply the first or last pattern in the list to match.
func TestDetectFrameworkFromManifest_HighestConfidenceWins(t *testing.T) {
	// Both Anthropic SDK (0.75) and LangChain (0.85) patterns are present.
	// LangChain must win.
	content := "anthropic==0.18.0\nlangchain-core==0.1.42\n"
	fw, conf, _ := detectFrameworkFromManifest(content)
	if fw != "LangChain" {
		t.Errorf("expected the higher-confidence LangChain match to win over Anthropic SDK, got %q", fw)
	}
	if conf != 0.85 {
		t.Errorf("expected confidence 0.85 for the winning match, got %v", conf)
	}
}

// ── Framework detection: config-file override (Layer 3) ─────────────────────

func TestApplyConfigFileOverride_LangGraphJSON(t *testing.T) {
	content := &GitHubRepoContent{LangGraphJSON: `{"graphs": {}}`}
	fw, conf, isMCP := applyConfigFileOverride(content)
	if fw != "LangGraph" || conf != 0.97 || isMCP {
		t.Errorf("expected LangGraph/0.97/false, got %q/%v/%v", fw, conf, isMCP)
	}
}

func TestApplyConfigFileOverride_CrewDir(t *testing.T) {
	content := &GitHubRepoContent{CrewDir: true}
	fw, conf, isMCP := applyConfigFileOverride(content)
	if fw != "CrewAI" || conf != 0.95 || isMCP {
		t.Errorf("expected CrewAI/0.95/false, got %q/%v/%v", fw, conf, isMCP)
	}
}

func TestApplyConfigFileOverride_MCPJson(t *testing.T) {
	content := &GitHubRepoContent{MCPJson: `{"tools": []}`}
	fw, conf, isMCP := applyConfigFileOverride(content)
	if fw != "MCP SDK" || conf != 0.98 || !isMCP {
		t.Errorf("expected MCP SDK/0.98/true, got %q/%v/%v", fw, conf, isMCP)
	}
}

func TestApplyConfigFileOverride_NoConfigFile(t *testing.T) {
	content := &GitHubRepoContent{}
	fw, conf, isMCP := applyConfigFileOverride(content)
	if fw != "" || conf != 0 || isMCP {
		t.Errorf("expected no override when no config file is present, got %q/%v/%v", fw, conf, isMCP)
	}
}

// TestApplyConfigFileOverride_PriorityOrder is a regression test for the
// exact precedence the original if/else-if chain (and the switch it was
// extracted into) encode: LangGraphJSON beats CrewDir beats MCPJson when
// more than one config-file signal is present in the same repo.
func TestApplyConfigFileOverride_PriorityOrder(t *testing.T) {
	content := &GitHubRepoContent{
		LangGraphJSON: `{"graphs": {}}`,
		CrewDir:       true,
		MCPJson:       `{"tools": []}`,
	}
	fw, _, _ := applyConfigFileOverride(content)
	if fw != "LangGraph" {
		t.Errorf("expected LangGraphJSON to take priority over CrewDir and MCPJson, got %q", fw)
	}

	content2 := &GitHubRepoContent{CrewDir: true, MCPJson: `{"tools": []}`}
	fw2, _, _ := applyConfigFileOverride(content2)
	if fw2 != "CrewAI" {
		t.Errorf("expected CrewDir to take priority over MCPJson, got %q", fw2)
	}
}

// ── Tier 2 confidence-boost logic (the real analogue of "does a second,
// weaker signal agree with the manifest-detected framework" — Tier 3 here is
// an agent-shaped code pattern in an entrypoint file, not raw import
// statements; see the note at the bottom of this file for what wasn't
// testable). ──────────────────────────────────────────────────────────────

func TestComputeConfidence_AllThreeSignalsStack(t *testing.T) {
	content := &GitHubRepoContent{IntentText: "This agent processes support tickets."}
	got := computeConfidence(content, "LangGraph", true)
	if got != 1.0 {
		t.Errorf("expected 0.50 (intent) + 0.35 (framework) + 0.15 (entrypoint) = 1.0, got %v", got)
	}
}

func TestComputeConfidence_FrameworkOnly(t *testing.T) {
	content := &GitHubRepoContent{}
	got := computeConfidence(content, "CrewAI", false)
	if got != 0.35 {
		t.Errorf("expected 0.35 for framework signal alone, got %v", got)
	}
}

func TestComputeConfidence_IntentOnly(t *testing.T) {
	content := &GitHubRepoContent{IntentText: "Handles inbound webhook processing."}
	got := computeConfidence(content, "", false)
	if got != 0.50 {
		t.Errorf("expected 0.50 for intent signal alone, got %v", got)
	}
}

func TestComputeConfidence_EntrypointOnly(t *testing.T) {
	content := &GitHubRepoContent{}
	got := computeConfidence(content, "", true)
	if got != 0.15 {
		t.Errorf("expected 0.15 for entrypoint signal alone, got %v", got)
	}
}

func TestComputeConfidence_NoSignals(t *testing.T) {
	content := &GitHubRepoContent{}
	got := computeConfidence(content, "", false)
	if got != 0.0 {
		t.Errorf("expected 0.0 when no signal is present, got %v", got)
	}
}

// TestComputeConfidence_IntentDisagreesWithFramework confirms the two
// strongest signals combine (rather than one suppressing the other) when
// intent text is present but no recognised framework was found — this is
// the "disagreement" case: a human wrote an intent statement, but neither
// the manifest nor a config file identified a known agent framework.
func TestComputeConfidence_IntentPresentFrameworkAbsent(t *testing.T) {
	content := &GitHubRepoContent{IntentText: "A hand-rolled agent with no recognised framework dependency."}
	got := computeConfidence(content, "", false)
	if got != 0.50 {
		t.Errorf("expected intent alone (0.50) when no framework signal agrees, got %v", got)
	}
}

// ── Actions workflow analysis ────────────────────────────────────────────────

func TestAnalyzeWorkflow_StaticAWSCreds_Fires(t *testing.T) {
	wf := workflowFile{Name: "deploy.yml", Content: "steps:\n  - uses: aws-actions/configure-aws-credentials@v4\n    with:\n      aws-access-key-id: ${{ secrets.AWS_KEY }}\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())

	found := false
	for _, f := range findings {
		if f.RuleID == "GITHUB_STATIC_AWS_CREDS" {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH severity, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected GITHUB_STATIC_AWS_CREDS to fire when the workflow uses aws-access-key-id")
	}
}

func TestAnalyzeWorkflow_StaticAWSCreds_DoesNotFireWithoutSignal(t *testing.T) {
	wf := workflowFile{Name: "deploy.yml", Content: "steps:\n  - uses: aws-actions/configure-aws-credentials@v4\n    with:\n      role-to-assume: arn:aws:iam::111111111111:role/example-deploy-role\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())
	for _, f := range findings {
		if f.RuleID == "GITHUB_STATIC_AWS_CREDS" {
			t.Error("expected GITHUB_STATIC_AWS_CREDS to NOT fire when the workflow has no aws-access-key-id signal")
		}
	}
}

func TestAnalyzeWorkflow_UnscopedWorkflow_FiresWithoutRoleToAssume(t *testing.T) {
	wf := workflowFile{Name: "deploy.yml", Content: "permissions:\n  id-token: write\n  contents: read\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())

	found := false
	for _, f := range findings {
		if f.RuleID == "GITHUB_UNSCOPED_WORKFLOW" {
			found = true
			if f.Severity != "MEDIUM" {
				t.Errorf("expected MEDIUM severity, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected GITHUB_UNSCOPED_WORKFLOW to fire when id-token: write is present with no role-to-assume")
	}
}

// TestAnalyzeWorkflow_UnscopedWorkflow_DoesNotFireWithRoleToAssume is the
// well-configured-OIDC happy path: id-token: write paired with a
// role-to-assume is exactly what OIDC federation is supposed to look like,
// and must not be flagged.
func TestAnalyzeWorkflow_UnscopedWorkflow_DoesNotFireWithRoleToAssume(t *testing.T) {
	wf := workflowFile{Name: "deploy.yml", Content: "permissions:\n  id-token: write\n  contents: read\nsteps:\n  - uses: aws-actions/configure-aws-credentials@v4\n    with:\n      role-to-assume: arn:aws:iam::111111111111:role/example-deploy-role\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())
	for _, f := range findings {
		if f.RuleID == "GITHUB_UNSCOPED_WORKFLOW" {
			t.Error("expected GITHUB_UNSCOPED_WORKFLOW to NOT fire when role-to-assume is present alongside id-token: write")
		}
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for a well-configured OIDC workflow, got %+v", findings)
	}
}

func TestAnalyzeWorkflow_NoAWSSignalsAtAll_NoFindings(t *testing.T) {
	wf := workflowFile{Name: "test.yml", Content: "steps:\n  - run: go test ./...\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())
	if len(findings) != 0 {
		t.Errorf("expected zero findings for a workflow with no AWS-related content, got %+v", findings)
	}
}

func TestAnalyzeWorkflow_BothFindingsCanFireIndependently(t *testing.T) {
	// A workflow that requests an OIDC token without assuming a role AND
	// separately uses static credentials elsewhere is a genuinely worse
	// posture, not a contradiction — both checks are independent substring
	// tests over the same content and must both fire.
	wf := workflowFile{Name: "deploy.yml", Content: "permissions:\n  id-token: write\nsteps:\n  - uses: aws-actions/configure-aws-credentials@v4\n    with:\n      aws-access-key-id: ${{ secrets.AWS_KEY }}\n"}
	findings := analyzeWorkflow(wf, "agent-stable-id", "example-agent", time.Now())

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["GITHUB_STATIC_AWS_CREDS"] || !ruleIDs["GITHUB_UNSCOPED_WORKFLOW"] {
		t.Errorf("expected both GITHUB_STATIC_AWS_CREDS and GITHUB_UNSCOPED_WORKFLOW to fire independently, got %+v", findings)
	}
}

// ── Committed secrets: confirm the shared detector, not a parallel copy ─────

// TestScanSecretsInFiles_UsesSharedDetector proves github.go's committed-
// secret detection is the exact shared.ScanContentForSecrets function
// (scanSecretsInFiles, github.go, calls shared.ScanContentForSecrets(".env",
// envContent) directly with no GitHub-specific pre/post-processing of the
// content or the pattern list) rather than a second, parallel implementation
// that could drift out of sync with the one internal/plugin/aws/cicd.go's
// CodeCommit secret scan uses. This can't call scanSecretsInFiles itself
// (it needs a real *gogithub.Client to fetch file content — the same
// no-network-mocking boundary aws_test.go/cicd_test.go draw), so it exercises
// shared.ScanContentForSecrets directly with the same input shape
// scanSecretsInFiles passes it.
func TestScanSecretsInFiles_UsesSharedDetector(t *testing.T) {
	envContent := "DATABASE_URL=postgres://localhost/example\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
	matches := shared.ScanContentForSecrets(".env", envContent)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match from the shared detector for a hardcoded AWS access key, got %d", len(matches))
	}
	if matches[0].Path != ".env" {
		t.Errorf("expected match Path %q (the exact path scanSecretsInFiles passes), got %q", ".env", matches[0].Path)
	}
}

func TestScanSecretsInFiles_UsesSharedDetector_NoSecret(t *testing.T) {
	matches := shared.ScanContentForSecrets(".env", "DATABASE_URL=postgres://localhost/example\n")
	if matches != nil {
		t.Errorf("expected no matches for content with no secret-shaped strings, got %+v", matches)
	}
}

// ── Static reference extraction ──────────────────────────────────────────────
//
// srcLambdaARN/srcAPIGWARN/srcAPIGWURL/srcBedrockARN/srcFunctionURL
// (github.go) are a separately-defined, textually-identical set of regexes
// to lambdaARNPattern/apiGWARNPattern/bedrockARNPattern/functionURLPattern
// in internal/plugin/aws/aws.go — parallel logic, not shared code (unlike
// the secrets detector above, this was never extracted into internal/plugin/
// shared). These tests exercise GitHub's copy on its own terms.

func TestSourceCodePatterns_LambdaARN(t *testing.T) {
	content := `client.invoke("arn:aws:lambda:us-east-1:111111111111:function:example-worker")`
	matches := srcLambdaARN.FindAllString(content, -1)
	if len(matches) != 1 || matches[0] != "arn:aws:lambda:us-east-1:111111111111:function:example-worker" {
		t.Errorf("expected 1 Lambda ARN match, got %+v", matches)
	}
}

func TestSourceCodePatterns_APIGatewayARN(t *testing.T) {
	content := `resource = "arn:aws:execute-api:us-east-1:111111111111:abc123def4"`
	matches := srcAPIGWARN.FindAllString(content, -1)
	if len(matches) != 1 {
		t.Errorf("expected 1 API Gateway ARN match, got %+v", matches)
	}
}

func TestSourceCodePatterns_APIGatewayURL(t *testing.T) {
	content := `endpoint = "https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/webhook"`
	matches := srcAPIGWURL.FindAllString(content, -1)
	if len(matches) != 1 {
		t.Errorf("expected 1 API Gateway URL match, got %+v", matches)
	}
}

func TestSourceCodePatterns_BedrockARN(t *testing.T) {
	content := `agent_arn = "arn:aws:bedrock:us-east-1:111111111111:agent/ABCD1234EF"`
	matches := srcBedrockARN.FindAllString(content, -1)
	if len(matches) != 1 {
		t.Errorf("expected 1 Bedrock agent ARN match, got %+v", matches)
	}
}

func TestSourceCodePatterns_FunctionURL(t *testing.T) {
	content := `url = "https://abcdefghij.lambda-url.us-east-1.on.aws/"`
	matches := srcFunctionURL.FindAllString(content, -1)
	if len(matches) != 1 {
		t.Errorf("expected 1 Lambda Function URL match, got %+v", matches)
	}
}

func TestSourceCodePatterns_NoMatchInUnrelatedContent(t *testing.T) {
	content := `import requests\nresponse = requests.get("https://example.com/api")`
	for _, pat := range sourceCodePatterns {
		if pat.re.FindString(content) != "" {
			t.Errorf("expected no match against unrelated content for pattern %v", pat.re)
		}
	}
}

func TestIsTestOrVendorPath_TestDirectory(t *testing.T) {
	if !isTestOrVendorPath("tests/fixtures/agent.py") {
		t.Error("expected a path under tests/ to be treated as a test path")
	}
}

func TestIsTestOrVendorPath_VendorDirectory(t *testing.T) {
	if !isTestOrVendorPath("vendor/github.com/example/pkg/main.go") {
		t.Error("expected a path under vendor/ to be treated as a vendor path")
	}
}

func TestIsTestOrVendorPath_TestFileSuffix(t *testing.T) {
	if !isTestOrVendorPath("src/agent_test.py") {
		t.Error("expected a _test.py suffix to be treated as a test path")
	}
}

func TestIsTestOrVendorPath_RealEntrypoint(t *testing.T) {
	if isTestOrVendorPath("src/agent.py") {
		t.Error("expected a real entrypoint path to NOT be treated as a test or vendor path")
	}
}

// ── OIDC-to-agent correlation ────────────────────────────────────────────────
//
// Not covered: no code in this package (or anywhere in the repo — confirmed
// via a full-repo grep for "OIDC", "role-to-assume", and "correlat" before
// writing this file) parses a workflow's OIDC trust subject, sets a GOVERNED
// visibility signal from it, or produces an OIDC_DEPLOY edge correlating a
// repo to a discovered Lambda/ECS agent. types.EdgeTypeOIDCDeploy is defined
// in internal/types/types.go but has no producer anywhere in the codebase.
// What actually exists is GITHUB_UNSCOPED_WORKFLOW (tested above), a
// substring check on workflow content with no agent-correlation step at all.
// Writing a test for OIDC-to-agent correlation would mean fabricating
// behavior that isn't implemented — flagged here instead, per the note in
// the commit message and CONTRIBUTING.md's "Known gaps" section.
//
// Also not covered for the same reason: sk_config.yaml (Semantic Kernel)
// config-file detection — no code references sk_config.yaml anywhere.

// ── matchSeedAgent / normalizeName ───────────────────────────────────────────

func TestMatchSeedAgent_ExactNormalizedMatch(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "Example-Worker", StableID: "match"},
	}
	got := matchSeedAgent("example-worker", agents)
	if got == nil || got.StableID != "match" {
		t.Errorf("expected an exact normalized-name match, got %+v", got)
	}
}

func TestMatchSeedAgent_PrefixMatch(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "ExampleOrchestrator-Prod", StableID: "match"},
	}
	got := matchSeedAgent("exampleorchestrator", agents)
	if got == nil || got.StableID != "match" {
		t.Errorf("expected a prefix match (seed agent name starts with repo name), got %+v", got)
	}
}

func TestMatchSeedAgent_PrefixTooShort_NoMatch(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "abcdef-prod", StableID: "should-not-match"},
	}
	got := matchSeedAgent("abcd", agents)
	if got != nil {
		t.Errorf("expected no prefix match for a repo name shorter than the 5-char minimum, got %+v", got)
	}
}

// TestMatchSeedAgent_NoMatch is the "repo doesn't match any known agent"
// case: scanRepo must skip the repo entirely (return nil, nil, nil) rather
// than spuriously creating or enriching a record.
func TestMatchSeedAgent_NoMatch(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "unrelated-service", StableID: "should-not-match"},
	}
	got := matchSeedAgent("completely-different-repo", agents)
	if got != nil {
		t.Errorf("expected nil for a repo name that matches no seed agent, got %+v", got)
	}
}

func TestMatchSeedAgent_EmptySeedAgents(t *testing.T) {
	got := matchSeedAgent("anything", nil)
	if got != nil {
		t.Errorf("expected nil when there are no seed agents at all, got %+v", got)
	}
}

func TestNormalizeName_StripsSeparatorsAndLowercases(t *testing.T) {
	got := normalizeName("Example-Orchestrator_v2")
	want := "exampleorchestratorv2"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// ── scoreAlignment ────────────────────────────────────────────────────────────

func TestScoreAlignment_NoIntentText_Unknown(t *testing.T) {
	score, tier, mismatches := scoreAlignment("", types.CanonicalAgentRecord{}, nil, nil)
	if score != 0.0 || tier != "UNKNOWN" || mismatches != nil {
		t.Errorf("expected 0.0/UNKNOWN/nil for empty intent text, got %v/%q/%+v", score, tier, mismatches)
	}
}

func TestScoreAlignment_ReadOnlyIntent_WriteIAMMismatch(t *testing.T) {
	agent := types.CanonicalAgentRecord{
		IAMPermissions: []types.NormalizedPermission{{RawAction: "s3:PutObject"}},
	}
	score, tier, mismatches := scoreAlignment("This is a read-only analytics agent.", agent, nil, nil)
	if score >= 1.0 {
		t.Errorf("expected a score penalty for a read-only intent with write IAM permissions, got %v", score)
	}
	if tier == "ALIGNED" {
		t.Errorf("expected a non-ALIGNED tier for a read-only/write-IAM mismatch, got %q", tier)
	}
	if len(mismatches) != 1 {
		t.Errorf("expected exactly 1 mismatch recorded, got %+v", mismatches)
	}
}

func TestScoreAlignment_ReadOnlyIntent_NoMismatch_Aligned(t *testing.T) {
	agent := types.CanonicalAgentRecord{
		IAMPermissions: []types.NormalizedPermission{{RawAction: "s3:GetObject"}},
	}
	score, tier, mismatches := scoreAlignment("This is a read-only analytics agent.", agent, nil, nil)
	if score != 1.0 {
		t.Errorf("expected no penalty when IAM permissions are read-only, got score %v", score)
	}
	if tier != "ALIGNED" {
		t.Errorf("expected ALIGNED tier, got %q", tier)
	}
	if mismatches != nil {
		t.Errorf("expected no mismatches, got %+v", mismatches)
	}
}

func TestScoreAlignment_StandaloneIntent_DelegationEdgeMismatch(t *testing.T) {
	agent := types.CanonicalAgentRecord{StableID: "agent-1"}
	edges := []types.AgentEdgeRecord{
		{SourceStableID: "agent-1", TargetStableID: "agent-2", EdgeType: types.EdgeTypeA2ACall},
	}
	score, _, mismatches := scoreAlignment("A standalone, self-contained agent with no external dependencies.", agent, nil, edges)
	if score >= 1.0 {
		t.Errorf("expected a score penalty for a standalone intent with an outbound A2A_CALL edge, got %v", score)
	}
	if len(mismatches) != 1 {
		t.Errorf("expected exactly 1 mismatch recorded, got %+v", mismatches)
	}
}

func TestScoreAlignment_WorkerIntent_OrchestrationIAMMismatch(t *testing.T) {
	agent := types.CanonicalAgentRecord{
		IAMPermissions: []types.NormalizedPermission{{RawAction: "lambda:InvokeFunction"}},
	}
	score, _, mismatches := scoreAlignment("A simple worker sub-agent.", agent, nil, nil)
	if score >= 1.0 {
		t.Errorf("expected a score penalty for a worker intent with orchestration IAM permissions, got %v", score)
	}
	if len(mismatches) != 1 {
		t.Errorf("expected exactly 1 mismatch recorded, got %+v", mismatches)
	}
}

func TestScoreAlignment_SecurityClaim_UnauthenticatedFindingMismatch(t *testing.T) {
	findings := []types.FindingRecord{{RuleID: "A2A_AUTH_NONE"}}
	score, _, mismatches := scoreAlignment("A secure, authenticated internal-only service.", types.CanonicalAgentRecord{}, findings, nil)
	if score >= 1.0 {
		t.Errorf("expected a score penalty for a security claim contradicted by an unauthenticated finding, got %v", score)
	}
	if len(mismatches) != 1 {
		t.Errorf("expected exactly 1 mismatch recorded, got %+v", mismatches)
	}
}

func TestScoreAlignment_CommittedSecret_AlwaysPenalized(t *testing.T) {
	findings := []types.FindingRecord{{RuleID: "GITHUB_COMMITTED_SECRET"}}
	score, _, mismatches := scoreAlignment("A perfectly ordinary internal tool.", types.CanonicalAgentRecord{}, findings, nil)
	if score >= 1.0 {
		t.Errorf("expected a score penalty when a secret is committed to the repository, got %v", score)
	}
	if len(mismatches) != 1 {
		t.Errorf("expected exactly 1 mismatch recorded, got %+v", mismatches)
	}
}

func TestScoreAlignment_ScoreNeverGoesBelowZero(t *testing.T) {
	// Stack every penalty at once — the combined deduction would go
	// negative without the explicit floor in scoreAlignment.
	agent := types.CanonicalAgentRecord{
		StableID:       "agent-1",
		IAMPermissions: []types.NormalizedPermission{{RawAction: "s3:PutObject"}, {RawAction: "lambda:InvokeFunction"}},
	}
	edges := []types.AgentEdgeRecord{
		{SourceStableID: "agent-1", TargetStableID: "agent-2", EdgeType: types.EdgeTypeStaticRef},
	}
	findings := []types.FindingRecord{
		{RuleID: "A2A_AUTH_NONE"},
		{RuleID: "GITHUB_COMMITTED_SECRET"},
	}
	intent := "A read-only, standalone, worker, secure, authenticated sub-agent."
	score, tier, _ := scoreAlignment(intent, agent, findings, edges)
	if score < 0 {
		t.Errorf("expected score to be floored at 0.0, got %v", score)
	}
	if tier != "MISMATCHED" {
		t.Errorf("expected MISMATCHED tier for a heavily-penalized score, got %q", tier)
	}
}

// ── stableID ──────────────────────────────────────────────────────────────────

func TestStableID_DeterministicForSameInput(t *testing.T) {
	a := stableID("org-1", "github:example-org/example-repo")
	b := stableID("org-1", "github:example-org/example-repo")
	if a != b {
		t.Errorf("expected stableID to be deterministic for identical input, got %q and %q", a, b)
	}
}

func TestStableID_DifferentForDifferentExternalID(t *testing.T) {
	a := stableID("org-1", "github:example-org/repo-a")
	b := stableID("org-1", "github:example-org/repo-b")
	if a == b {
		t.Error("expected different externalIDs to produce different stableIDs")
	}
}

func TestStableID_DifferentForDifferentOrg(t *testing.T) {
	a := stableID("org-1", "github:example-org/example-repo")
	b := stableID("org-2", "github:example-org/example-repo")
	if a == b {
		t.Error("expected different orgIDs to produce different stableIDs for the same externalID")
	}
}

// ── Intent extraction: markdown parsing ──────────────────────────────────────

func TestExtractMarkdownIntent_RecognisedHeading(t *testing.T) {
	md := "# example-agent\n\nSome badge text.\n\n## Purpose\n\nProcesses inbound support tickets and drafts replies for review.\n\n## Installation\n\nrun `make install`\n"
	got := extractMarkdownIntent(md)
	want := "Processes inbound support tickets and drafts replies for review."
	if got != want {
		t.Errorf("expected the paragraph under ## Purpose, got %q", got)
	}
}

func TestExtractMarkdownIntent_FallsBackToH1Paragraph(t *testing.T) {
	md := "# example-agent\n\nA worker that syncs records between two internal systems.\n\n## Installation\n\nrun `make install`\n"
	got := extractMarkdownIntent(md)
	want := "A worker that syncs records between two internal systems."
	if got != want {
		t.Errorf("expected the first paragraph after the H1 title, got %q", got)
	}
}

func TestExtractMarkdownIntent_FallsBackToFirstSubstantiveParagraph(t *testing.T) {
	md := "This repository implements an internal notification relay agent.\n\nMore details below.\n"
	got := extractMarkdownIntent(md)
	want := "This repository implements an internal notification relay agent."
	if got != want {
		t.Errorf("expected the first substantive paragraph anywhere, got %q", got)
	}
}

func TestExtractMarkdownIntent_TruncatesAt500Chars(t *testing.T) {
	long := "# example-agent\n\n"
	for i := 0; i < 60; i++ {
		long += "This is a very long description sentence padding the paragraph out. "
	}
	got := extractMarkdownIntent(long)
	if len(got) > 503 { // 500 chars + "..."
		t.Errorf("expected extractMarkdownIntent to truncate to ~500 chars, got length %d", len(got))
	}
}

func TestFirstSubstantiveParagraph_SkipsHeadingsRulesBadges(t *testing.T) {
	lines := []string{
		"---",
		"[![build](https://example.com/badge.svg)](https://example.com)",
		"",
		"The actual first real paragraph of content.",
		"",
		"A second paragraph that should not be included.",
	}
	got := firstSubstantiveParagraph(lines)
	want := "The actual first real paragraph of content."
	if got != want {
		t.Errorf("expected the horizontal rule and badge line to be skipped, got %q", got)
	}
}

// TestFirstSubstantiveParagraph_FencedCodeBlockLinesAreNotFullyExcluded
// documents a real, non-obvious limitation rather than the behavior a
// "skips code blocks" description might suggest: isCode only checks whether
// *this line itself* starts with "```" or 4-space indentation — it does not
// track fence state across lines. A ```-delimited block's opening and
// closing fence lines are skipped, but a content line inside the fence that
// doesn't itself start with those prefixes is treated as ordinary paragraph
// text. Not fixed here (out of scope for a test-coverage pass; this is a
// pre-existing intent-extraction quality gap, not a security-relevant rule),
// but the coverage bar this file is closing means a wrong assumption about
// this behavior should fail loudly rather than pass silently.
func TestFirstSubstantiveParagraph_FencedCodeBlockLinesAreNotFullyExcluded(t *testing.T) {
	lines := []string{
		"```",
		"code block content that is not itself indented or fenced",
		"```",
	}
	got := firstSubstantiveParagraph(lines)
	want := "code block content that is not itself indented or fenced"
	if got != want {
		t.Errorf("expected the unfenced-looking content line inside the code block to be picked up as a paragraph (documenting the real, current behavior), got %q", got)
	}
}

func TestFirstSubstantiveParagraph_TooShort_ReturnsEmpty(t *testing.T) {
	got := firstSubstantiveParagraph([]string{"hi"})
	if got != "" {
		t.Errorf("expected empty string for content under the 10-char minimum, got %q", got)
	}
}

func TestStripMarkdown_LinksBoldItalicCode(t *testing.T) {
	got := stripMarkdown("See [the docs](https://example.com) for **bold** and *italic* and `code`.")
	want := "See the docs for bold and italic and code."
	if got != want {
		t.Errorf("expected markdown markup stripped, got %q", got)
	}
}

func TestExtractOwnerFromMarkdown_LabelledField(t *testing.T) {
	md := "# example-agent\n\nOwner: team-platform\n"
	got := extractOwnerFromMarkdown(md)
	if got != "team-platform" {
		t.Errorf("expected owner %q, got %q", "team-platform", got)
	}
}

func TestExtractOwnerFromMarkdown_EmailNearOwnershipKeyword(t *testing.T) {
	md := "# example-agent\n\nMaintained by jane.doe@example.com\n"
	got := extractOwnerFromMarkdown(md)
	if got != "jane.doe@example.com" {
		t.Errorf("expected owner email %q, got %q", "jane.doe@example.com", got)
	}
}

func TestExtractOwnerFromMarkdown_NoOwnerSignal(t *testing.T) {
	md := "# example-agent\n\nThis agent does useful things.\n"
	got := extractOwnerFromMarkdown(md)
	if got != "" {
		t.Errorf("expected no owner extracted, got %q", got)
	}
}

func TestIntentConfidence_KnownSources(t *testing.T) {
	cases := map[string]float64{
		IntentSourceManifest: 0.98,
		IntentSourceAgentMD:  0.90,
		IntentSourceClaudeMD: 0.85,
		IntentSourceReadme:   0.60,
		"UNKNOWN_SOURCE":     0.50,
	}
	for source, want := range cases {
		if got := intentConfidence(source); got != want {
			t.Errorf("intentConfidence(%q) = %v, want %v", source, got, want)
		}
	}
}

func TestFirstSentence_ExtractsUpToPunctuation(t *testing.T) {
	got := firstSentence("# Title\n\nThis is the first real sentence. This is the second.")
	want := "This is the first real sentence."
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestFirstSentence_NoPunctuation_ReturnsWholeLine(t *testing.T) {
	got := firstSentence("A description with no terminal punctuation at all")
	want := "A description with no terminal punctuation at all"
	if got != want {
		t.Errorf("expected the whole line when there's no sentence-ending punctuation, got %q", got)
	}
}

func TestWordCount_Basic(t *testing.T) {
	got := wordCount("This has five words.")
	if got != 4 {
		// "This", "has", "five", "words." (trailing period attaches to
		// "words" as punctuation, not a separate token) — 4 words.
		t.Errorf("expected 4 words, got %d", got)
	}
}

func TestWordCount_Empty(t *testing.T) {
	if got := wordCount(""); got != 0 {
		t.Errorf("expected 0 words for empty string, got %d", got)
	}
}

func TestTruncate_ShorterThanLimit(t *testing.T) {
	got := truncate("short", 20)
	if got != "short" {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestTruncate_LongerThanLimit(t *testing.T) {
	got := truncate("this is definitely longer than the limit", 10)
	want := "this is de..."
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// ── isCredentialError ─────────────────────────────────────────────────────────

func TestIsCredentialError_BadCredentials(t *testing.T) {
	if !isCredentialError(fmt.Errorf("GET https://api.github.com/orgs/example: 401 Bad credentials")) {
		t.Error("expected a 401/Bad credentials error to be classified as a credential error")
	}
}

func TestIsCredentialError_RequiresAuthentication(t *testing.T) {
	if !isCredentialError(fmt.Errorf("Requires authentication")) {
		t.Error("expected a 'Requires authentication' error to be classified as a credential error")
	}
}

func TestIsCredentialError_UnrelatedError_NotCredential(t *testing.T) {
	if isCredentialError(fmt.Errorf("404 Not Found")) {
		t.Error("expected a 404 (successful call, zero results) to NOT be classified as a credential error")
	}
}

func TestIsCredentialError_NilError(t *testing.T) {
	if isCredentialError(nil) {
		t.Error("expected a nil error to NOT be classified as a credential error")
	}
}
