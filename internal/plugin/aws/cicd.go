// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/specter-demo/specter-scanner/internal/plugin/shared"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// scanCICD implements Step 6: Source/CI-CD (spec section 4.2). It discovers
// CodeCommit repositories, CodeBuild projects, CodePipeline pipelines,
// CodeDeploy applications, and ECR repositories, and correlates them against
// agents already discovered in Steps 1-3 of the same scan by name.
//
// Intent detection reuses the exact same mechanism as every other platform:
// this function only populates agent.IntentStatement / IntentSource /
// IntentOwner on a match. The MISSING_INTENT_DECLARATION finding itself is
// emitted centrally by internal/analysis/staticref, not here — see
// checkCodeCommitIntent.
func (p *Plugin) scanCICD(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	var findings []types.FindingRecord
	var errs []error

	if f, err := p.scanCodeCommit(ctx, knownAgents); err != nil {
		errs = append(errs, err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanCodeBuild(ctx, knownAgents); err != nil {
		errs = append(errs, err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanECRRepos(ctx, knownAgents); err != nil {
		errs = append(errs, err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanCodePipeline(ctx, knownAgents); err != nil {
		errs = append(errs, err)
	} else {
		findings = append(findings, f...)
	}

	// CodeDeploy: enumerated for deployment-target context only (spec: "no
	// new finding type required unless a natural one emerges" — none did).
	if err := p.scanCodeDeployContext(ctx); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return findings, errs[0]
	}
	return findings, nil
}

// scanCodeCommit lists repositories, checks each for a formal intent
// declaration (same file-priority convention as the GitHub plugin:
// .specter/manifest.yaml, AGENT.md, CLAUDE.md — no README fallback here,
// since CodeCommit repos are correlated to an already-known agent rather
// than creating a standalone record), and scans root-level files for
// hardcoded secrets using the shared detector.
//
// A repo only contributes intent/secret data to an agent already discovered
// in Steps 1-3 whose name matches the repo — mirroring matchSeedAgent in
// the GitHub plugin exactly, just against knownAgents instead of SeedAgents.
func (p *Plugin) scanCodeCommit(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	client := codecommit.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var findings []types.FindingRecord

	var nextToken *string
	for {
		out, err := client.ListRepositories(ctx, &codecommit.ListRepositoriesInput{NextToken: nextToken})
		if err != nil {
			return findings, fmt.Errorf("ListRepositories: %w", err)
		}

		for _, r := range out.Repositories {
			repoName := aws.ToString(r.RepositoryName)
			matched := matchAgentByName(repoName, knownAgents)
			if matched == nil {
				// No corresponding agent discovered elsewhere in this scan —
				// nothing to attribute findings to. Skip, same as the GitHub
				// plugin skipping repos with no seed-agent match.
				continue
			}

			repoOut, err := client.GetRepository(ctx, &codecommit.GetRepositoryInput{RepositoryName: r.RepositoryName})
			if err != nil {
				log.Printf("aws: codecommit GetRepository %s: %v", repoName, err)
				continue
			}
			meta := repoOut.RepositoryMetadata
			branch := aws.ToString(meta.DefaultBranch)
			if branch == "" {
				branch = "main"
			}

			// Records that this agent has an associated source repo — this is
			// the signal internal/analysis/staticref.isAIAgent() uses to
			// decide whether MISSING_INTENT_DECLARATION applies. Without it,
			// an ECS/Lambda agent with no framework signal and no manifest
			// (exactly PipelineForge-Prod's case) would never be checked for
			// a missing intent declaration at all, regardless of whether one
			// exists — the CodeCommit repo it's built from is precisely
			// what makes it a candidate for that check.
			matched.RepoName = repoName
			matched.RepoURL = aws.ToString(meta.CloneUrlHttp)

			p.checkCodeCommitIntent(ctx, client, repoName, branch, matched)
			findings = append(findings, p.scanCodeCommitSecrets(ctx, client, repoName, branch, matched, now)...)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return findings, nil
}

// checkCodeCommitIntent looks for an intent file in the same priority order
// as the GitHub plugin's extractIntentDeclaration (manifest.yaml > AGENT.md
// > CLAUDE.md), and sets IntentStatement/IntentSource/IntentOwner on the
// matched agent if found. Leaving these fields empty on a miss is the
// correct behavior — internal/analysis/staticref.intentFindings reads these
// same fields for every platform and emits MISSING_INTENT_DECLARATION
// itself; duplicating that emission here would double-fire the finding.
func (p *Plugin) checkCodeCommitIntent(ctx context.Context, client *codecommit.Client, repoName, branch string, agent *types.CanonicalAgentRecord) {
	if content, ok := getCodeCommitFile(ctx, client, repoName, branch, ".specter/manifest.yaml"); ok {
		if m, ok := shared.ParseSpecterManifest(content); ok && m.Intent != "" {
			agent.IntentStatement = shared.TruncateForEvidence(m.Intent, 500)
			agent.IntentSource = "MANIFEST"
			agent.IntentOwner = m.Owner
			return
		}
	}
	if content, ok := getCodeCommitFile(ctx, client, repoName, branch, "AGENT.md"); ok {
		agent.IntentStatement = extractFirstParagraph(content, 500)
		agent.IntentSource = "AGENT_MD"
		agent.IntentOwner = extractOwnerLine(content)
		return
	}
	if content, ok := getCodeCommitFile(ctx, client, repoName, branch, "CLAUDE.md"); ok {
		agent.IntentStatement = extractFirstParagraph(content, 500)
		agent.IntentSource = "CLAUDE_MD"
		agent.IntentOwner = extractOwnerLine(content)
		return
	}
	// No manifest, AGENT.md, or CLAUDE.md — IntentStatement stays empty.
	// staticref.intentFindings fires MISSING_INTENT_DECLARATION for this case.
}

// scanCodeCommitSecrets checks root-level files most likely to carry a
// hardcoded credential, reusing shared.ScanContentForSecrets — the exact
// same detector the GitHub plugin uses, not a second implementation.
func (p *Plugin) scanCodeCommitSecrets(ctx context.Context, client *codecommit.Client, repoName, branch string, agent *types.CanonicalAgentRecord, now time.Time) []types.FindingRecord {
	var findings []types.FindingRecord
	candidates := []string{".env", "buildspec.yml", "requirements.txt", "config.py", "config.json"}

	for _, path := range candidates {
		content, ok := getCodeCommitFile(ctx, client, repoName, branch, path)
		if !ok {
			continue
		}
		for _, m := range shared.ScanContentForSecrets(path, content) {
			evidence, _ := json.Marshal(map[string]string{
				"repository": repoName,
				"path":       m.Path,
				"pattern":    m.Pattern,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "GITHUB_COMMITTED_SECRET",
				Severity:      "CRITICAL",
				AgentStableID: agent.StableID,
				AgentName:     agent.Name,
				Title:         "Hardcoded secret committed to repository",
				Description:   fmt.Sprintf("CodeCommit repository %s contains a committed secret in %s.", repoName, m.Path),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}
	}
	return findings
}

// getCodeCommitFile fetches one file's content, returning ok=false on any
// error (including "does not exist") — same swallow-and-skip behavior as
// the GitHub plugin's fetchFileContent, since a missing file is the
// expected, common case, not an error worth failing the scan over.
func getCodeCommitFile(ctx context.Context, client *codecommit.Client, repoName, branch, path string) (string, bool) {
	out, err := client.GetFile(ctx, &codecommit.GetFileInput{
		RepositoryName:  aws.String(repoName),
		FilePath:        aws.String(path),
		CommitSpecifier: aws.String(branch),
	})
	if err != nil || len(out.FileContent) == 0 {
		return "", false
	}
	return string(out.FileContent), true
}

// scanCodeBuild lists projects and inspects each service role's IAM policy
// for iam:PassRole on Resource: "*" — a check with no existing generic
// equivalent (unlike the Secrets Manager wildcard, iam:PassRole is not in
// the sensitiveActions set used by hasWildcardOnSensitive, since granting
// it broadly on non-CI roles is common and not itself a signal; the
// CodeBuild-specific context of "service role that also has broad PassRole"
// is what makes this a real, actionable finding).
func (p *Plugin) scanCodeBuild(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	client := codebuild.NewFromConfig(p.awsConf)
	iamClient := iam.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var findings []types.FindingRecord

	listOut, err := client.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return findings, fmt.Errorf("ListProjects: %w", err)
	}
	if len(listOut.Projects) == 0 {
		return findings, nil
	}

	batchOut, err := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: listOut.Projects})
	if err != nil {
		return findings, fmt.Errorf("BatchGetProjects: %w", err)
	}

	for _, proj := range batchOut.Projects {
		projectName := aws.ToString(proj.Name)
		roleArn := aws.ToString(proj.ServiceRole)
		if roleArn == "" {
			continue
		}
		roleName := roleNameFromARN(roleArn)
		if roleName == "" {
			continue
		}

		// Every finding must be attributable to an agent already present in
		// this scan's agent list — the platform's ingest pipeline rejects
		// findings whose AgentStableID doesn't match a posted agent. A
		// CodeBuild project with no correlated agent (e.g. shared/generic
		// build tooling not tied to one specific product) is skipped rather
		// than attributed to a synthesized identity that doesn't exist.
		matched := matchAgentByName(projectName, knownAgents)
		if matched == nil {
			continue
		}

		if hasWildcardPassRole(ctx, iamClient, roleName) {
			evidence, _ := json.Marshal(map[string]string{
				"project": projectName,
				"roleArn": roleArn,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "CODEBUILD_WILDCARD_SERVICE_ROLE",
				Severity:      "HIGH",
				AgentStableID: matched.StableID,
				AgentName:     matched.Name,
				Title:         "CodeBuild service role grants iam:PassRole on all resources",
				Description:   fmt.Sprintf("CodeBuild project %s's service role (%s) grants iam:PassRole on Resource: \"*\" instead of scoped role ARNs.", projectName, roleArn),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}
	}

	return findings, nil
}

// hasWildcardPassRole checks a role's inline and managed policies for
// iam:PassRole granted on Resource: "*". Reuses parseIAMPolicy (the same
// policy-document parser enrichIAMRole uses) rather than writing a second
// JSON-statement parser.
func hasWildcardPassRole(ctx context.Context, iamClient *iam.Client, roleName string) bool {
	listOut, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err == nil {
		for _, policyName := range listOut.PolicyNames {
			policyOut, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				continue
			}
			perms := parseIAMPolicy(decodeIAMPolicyDoc(aws.ToString(policyOut.PolicyDocument)))
			if hasActionOnWildcard(perms, "iam:passrole") {
				return true
			}
		}
	}

	attachedOut, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	if err == nil {
		for _, attached := range attachedOut.AttachedPolicies {
			policyOut, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: attached.PolicyArn})
			if err != nil {
				continue
			}
			versionOut, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: attached.PolicyArn,
				VersionId: policyOut.Policy.DefaultVersionId,
			})
			if err != nil {
				continue
			}
			perms := parseIAMPolicy(decodeIAMPolicyDoc(aws.ToString(versionOut.PolicyVersion.Document)))
			if hasActionOnWildcard(perms, "iam:passrole") {
				return true
			}
		}
	}

	return false
}

// hasActionOnWildcard reports whether perms contains action (case-insensitive)
// granted with Resource: "*".
func hasActionOnWildcard(perms []types.NormalizedPermission, action string) bool {
	for _, perm := range perms {
		if perm.ResourceScope == "*" && strings.EqualFold(perm.RawAction, action) {
			return true
		}
	}
	return false
}

// scanECRRepos checks image_scanning_configuration.scan_on_push for every
// ECR repository.
func (p *Plugin) scanECRRepos(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	client := ecr.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var findings []types.FindingRecord

	var nextToken *string
	for {
		out, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: nextToken})
		if err != nil {
			return findings, fmt.Errorf("DescribeRepositories: %w", err)
		}

		for _, repo := range out.Repositories {
			name := aws.ToString(repo.RepositoryName)
			if !ecrScanOnPushDisabled(repo.ImageScanningConfiguration) {
				continue
			}

			// Same attribution requirement as CodeBuild: a shared/generic
			// ECR repo (e.g. one image repo reused by multiple unrelated
			// services) that doesn't correlate to one specific agent is
			// skipped rather than misattributed.
			matched := matchAgentByName(name, knownAgents)
			if matched == nil {
				continue
			}

			evidence, _ := json.Marshal(map[string]string{
				"repositoryName": name,
				"repositoryArn":  aws.ToString(repo.RepositoryArn),
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "ECR_SCAN_ON_PUSH_DISABLED",
				Severity:      "MEDIUM",
				AgentStableID: matched.StableID,
				AgentName:     matched.Name,
				Title:         "ECR repository has image scanning disabled",
				Description:   fmt.Sprintf("ECR repository %s has imageScanningConfiguration.scanOnPush set to false.", name),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return findings, nil
}

// ecrScanOnPushDisabled reports whether an ECR repository's scan-on-push is
// off. A nil ImageScanningConfiguration means the repo was created without
// specifying it, which AWS defaults to false (not scanned) — that counts
// as disabled, same as an explicit scanOnPush: false.
func ecrScanOnPushDisabled(cfg *ecrtypes.ImageScanningConfiguration) bool {
	return cfg == nil || !cfg.ScanOnPush
}

// scanCodePipeline lists pipelines and checks whether a Manual Approval
// action exists between any Build-category stage and the following
// Deploy-category stage.
func (p *Plugin) scanCodePipeline(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	client := codepipeline.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var findings []types.FindingRecord

	var nextToken *string
	for {
		listOut, err := client.ListPipelines(ctx, &codepipeline.ListPipelinesInput{NextToken: nextToken})
		if err != nil {
			return findings, fmt.Errorf("ListPipelines: %w", err)
		}

		for _, summary := range listOut.Pipelines {
			name := aws.ToString(summary.Name)
			getOut, err := client.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: aws.String(name)})
			if err != nil {
				log.Printf("aws: codepipeline GetPipeline %s: %v", name, err)
				continue
			}
			if getOut.Pipeline == nil {
				continue
			}
			if hasApprovalBetweenBuildAndDeploy(getOut.Pipeline.Stages) {
				continue
			}

			matched := matchAgentByName(name, knownAgents)
			if matched == nil {
				continue
			}

			evidence, _ := json.Marshal(map[string]interface{}{
				"pipelineName": name,
				"stages":       stageNames(getOut.Pipeline.Stages),
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "CODEPIPELINE_NO_APPROVAL_GATE",
				Severity:      "HIGH",
				AgentStableID: matched.StableID,
				AgentName:     matched.Name,
				Title:         "CodePipeline has no manual approval gate before deploy",
				Description:   fmt.Sprintf("Pipeline %s has no Manual Approval action between its Build-category and Deploy-category stages.", name),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}

		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	return findings, nil
}

// hasApprovalBetweenBuildAndDeploy reports whether an Approval-category
// action exists in a stage positioned after the first Build-category stage
// and before the first Deploy-category stage that follows it.
func hasApprovalBetweenBuildAndDeploy(stages []cptypes.StageDeclaration) bool {
	buildIdx, deployIdx := -1, -1
	for i, s := range stages {
		for _, a := range s.Actions {
			if a.ActionTypeId == nil {
				continue
			}
			switch a.ActionTypeId.Category {
			case cptypes.ActionCategoryBuild:
				if buildIdx == -1 {
					buildIdx = i
				}
			case cptypes.ActionCategoryDeploy:
				if deployIdx == -1 && buildIdx != -1 {
					deployIdx = i
				}
			}
		}
	}
	if buildIdx == -1 || deployIdx == -1 || deployIdx <= buildIdx {
		// No Build->Deploy pair to gate — nothing to flag either way.
		return true
	}
	for i := buildIdx + 1; i < deployIdx; i++ {
		for _, a := range stages[i].Actions {
			if a.ActionTypeId != nil && a.ActionTypeId.Category == cptypes.ActionCategoryApproval {
				return true
			}
		}
		// An approval action can also sit inside the deploy stage itself,
		// ahead of the deploy action — check same-stage ordering there too.
	}
	for _, a := range stages[deployIdx].Actions {
		if a.ActionTypeId != nil && a.ActionTypeId.Category == cptypes.ActionCategoryApproval {
			return true
		}
	}
	return false
}

func stageNames(stages []cptypes.StageDeclaration) []string {
	names := make([]string, 0, len(stages))
	for _, s := range stages {
		names = append(names, aws.ToString(s.Name))
	}
	return names
}

// scanCodeDeployContext enumerates CodeDeploy applications and deployment
// groups for deployment-target context. Per spec: no new finding type is
// forced here — enumeration alone gives the scanner visibility into what
// PipelineForge-CI-style pipelines actually deploy to.
func (p *Plugin) scanCodeDeployContext(ctx context.Context) error {
	client := codedeploy.NewFromConfig(p.awsConf)

	appsOut, err := client.ListApplications(ctx, &codedeploy.ListApplicationsInput{})
	if err != nil {
		return fmt.Errorf("ListApplications: %w", err)
	}
	for _, appName := range appsOut.Applications {
		dgOut, err := client.ListDeploymentGroups(ctx, &codedeploy.ListDeploymentGroupsInput{
			ApplicationName: aws.String(appName),
		})
		if err != nil {
			log.Printf("aws: codedeploy ListDeploymentGroups %s: %v", appName, err)
			continue
		}
		log.Printf("aws: codedeploy application %s has %d deployment group(s)", appName, len(dgOut.DeploymentGroups))
	}
	return nil
}

// matchAgentByName finds an already-discovered agent whose name correlates
// with candidateName (a CodeCommit repo, CodeBuild project, etc.).
//
// CI/CD resource families don't share the GitHub plugin's repo==agent-name
// convention (internal/plugin/github/github.go's matchSeedAgent): a single
// product like PipelineForge has a CodeCommit repo named "pipelineforge-ci",
// an ECS service named "PipelineForge-Prod", a CodeBuild project named
// "pipelineforge-build" — related by a shared stem, but with neither name a
// strict prefix of the other. Exact match is tried first; the fallback is
// longest-common-prefix length, not strict HasPrefix.
func matchAgentByName(candidateName string, agents []types.CanonicalAgentRecord) *types.CanonicalAgentRecord {
	norm := normalizeForMatch(candidateName)
	if norm == "" {
		return nil
	}

	for i := range agents {
		if normalizeForMatch(agents[i].Name) == norm {
			return &agents[i]
		}
	}

	const minStemLen = 8
	var best *types.CanonicalAgentRecord
	bestStem := 0
	bestLenDiff := 1 << 30
	for i := range agents {
		agentNorm := normalizeForMatch(agents[i].Name)
		stem := commonPrefixLen(agentNorm, norm)
		if stem < minStemLen {
			continue
		}
		// Among candidates sharing the longest common-prefix stem, prefer
		// the one whose overall length is closest to the search term — e.g.
		// ECR repo "pipelineforge" and CodeCommit repo "pipelineforge-ci"
		// both have a 13-char common prefix with *both*
		// "PipelineForge-Prod" and "PipelineForge-DeployValidator", since
		// "pipelineforge" is a complete prefix of each. Minimizing the
		// length difference correctly prefers "PipelineForge-Prod" (a
		// small suffix variant) over "...DeployValidator" (a much longer,
		// unrelated Lambda that just happens to share the product stem).
		lenDiff := len(agentNorm) - len(norm)
		if lenDiff < 0 {
			lenDiff = -lenDiff
		}
		if stem > bestStem || (stem == bestStem && lenDiff < bestLenDiff) {
			best = &agents[i]
			bestStem = stem
			bestLenDiff = lenDiff
		}
	}
	return best
}

// commonPrefixLen returns the length of the longest shared prefix of a and b.
func commonPrefixLen(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func normalizeForMatch(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func roleNameFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// -- intent-file parsing helpers, mirroring the GitHub plugin's approach --
// AGENT.md/CLAUDE.md use a lightweight paragraph extractor here rather than
// the GitHub plugin's full extractMarkdownIntent (heading-aware, multi-pass
// search) — real markdown parsing isn't worth a dependency for a 2-file
// fallback path when .specter/manifest.yaml (the formal, structured source)
// already covers the common case via shared.ParseSpecterManifest above.

// extractFirstParagraph returns the first substantive non-heading paragraph
// of a markdown document, capped at maxLen.
func extractFirstParagraph(text string, maxLen int) string {
	var buf []string
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			if len(buf) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "```") || strings.HasPrefix(line, "---") {
			if len(buf) > 0 {
				break
			}
			continue
		}
		buf = append(buf, line)
	}
	result := strings.Join(buf, " ")
	if len(result) > maxLen {
		result = result[:maxLen] + "..."
	}
	return result
}

// extractOwnerLine looks for an "Owner:" / "Maintainer:" labelled line.
func extractOwnerLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		for _, label := range []string{"owner:", "maintainer:", "contact:"} {
			if strings.HasPrefix(lower, label) {
				return strings.TrimSpace(trimmed[len(label):])
			}
		}
	}
	return ""
}
