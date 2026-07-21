// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"net/url"
	"testing"

	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ── CODEBUILD_WILDCARD_SERVICE_ROLE ──────────────────────────────────────────
//
// hasWildcardPassRole itself takes a real *iam.Client and can't be called
// without live AWS credentials, but the bug it had (silently finding
// nothing) lived entirely in decodeIAMPolicyDoc + parseIAMPolicy +
// hasActionOnWildcard — the exact pure-function chain hasWildcardPassRole
// calls on every policy document it fetches. These tests exercise that
// chain directly.

func TestHasActionOnWildcard_WildcardPresent(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"*"}]}`
	perms := parseIAMPolicy(policy)
	if !hasActionOnWildcard(perms, "iam:passrole") {
		t.Error("expected iam:PassRole with Resource:* to be detected as a wildcard grant")
	}
}

func TestHasActionOnWildcard_ScopedResource_NoFinding(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"arn:aws:iam::123456789012:role/example-execution-role"}]}`
	perms := parseIAMPolicy(policy)
	if hasActionOnWildcard(perms, "iam:passrole") {
		t.Error("expected iam:PassRole scoped to a specific role ARN to NOT be flagged as a wildcard grant")
	}
}

// TestHasActionOnWildcard_PercentEncodedPolicy is a regression test for the
// exact bug caught during live validation: IAM's GetRolePolicy and
// GetPolicyVersion return the policy document percent-encoded, and without
// decodeIAMPolicyDoc, json.Unmarshal inside parseIAMPolicy fails silently
// (parseIAMPolicy returns nil on a parse error), making
// hasActionOnWildcard incorrectly return false even when the real policy
// has a genuine wildcard grant. This must never regress silently again.
func TestHasActionOnWildcard_PercentEncodedPolicy(t *testing.T) {
	raw := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"*","Sid":"OverbroadPassRole"}]}`
	encoded := url.QueryEscape(raw)

	// Sanity check the fixture: an encoded document must not parse as
	// valid JSON directly, or this test would pass without exercising the
	// decode step at all.
	if directPerms := parseIAMPolicy(encoded); hasActionOnWildcard(directPerms, "iam:passrole") {
		t.Fatal("test fixture is broken: percent-encoded document parsed as valid JSON without decoding — this test isn't exercising the bug it's meant to catch")
	}

	decoded := decodeIAMPolicyDoc(encoded)
	perms := parseIAMPolicy(decoded)
	if !hasActionOnWildcard(perms, "iam:passrole") {
		t.Error("decodeIAMPolicyDoc + parseIAMPolicy failed to detect a wildcard iam:PassRole grant in a percent-encoded policy document — this is the exact bug found during live validation against real AWS")
	}
}

func TestDecodeIAMPolicyDoc_FallsBackOnUndecodable(t *testing.T) {
	// A string containing a lone '%' followed by non-hex characters is not
	// valid percent-encoding; QueryUnescape errors, and decodeIAMPolicyDoc
	// must return the original string rather than an empty one, so
	// parseIAMPolicy still gets a chance to fail cleanly (empty perms)
	// rather than decodeIAMPolicyDoc silently eating the content.
	in := `{"not": "percent encoded", "has_percent": "50%"}`
	out := decodeIAMPolicyDoc(in)
	if out != in {
		t.Errorf("expected decodeIAMPolicyDoc to return the original string unchanged when it isn't percent-encoded, got %q", out)
	}
}

// ── ECR_SCAN_ON_PUSH_DISABLED ─────────────────────────────────────────────────

func TestEcrScanOnPushDisabled_Disabled(t *testing.T) {
	cfg := &ecrtypes.ImageScanningConfiguration{ScanOnPush: false}
	if !ecrScanOnPushDisabled(cfg) {
		t.Error("expected scanOnPush: false to be reported as disabled")
	}
}

func TestEcrScanOnPushDisabled_Enabled(t *testing.T) {
	cfg := &ecrtypes.ImageScanningConfiguration{ScanOnPush: true}
	if ecrScanOnPushDisabled(cfg) {
		t.Error("expected scanOnPush: true to NOT be reported as disabled")
	}
}

func TestEcrScanOnPushDisabled_MissingConfig(t *testing.T) {
	// A repository created without specifying image scanning at all has a
	// nil ImageScanningConfiguration — AWS defaults this to "not scanned",
	// so it must count as disabled, not be skipped as "no data".
	if !ecrScanOnPushDisabled(nil) {
		t.Error("expected a nil ImageScanningConfiguration (scanning never configured) to count as disabled")
	}
}

// ── CODEPIPELINE_NO_APPROVAL_GATE ─────────────────────────────────────────────

func stage(name string, categories ...cptypes.ActionCategory) cptypes.StageDeclaration {
	name2 := name
	actions := make([]cptypes.ActionDeclaration, len(categories))
	for i, c := range categories {
		c2 := c
		actions[i] = cptypes.ActionDeclaration{
			ActionTypeId: &cptypes.ActionTypeId{Category: c2},
		}
	}
	return cptypes.StageDeclaration{Name: &name2, Actions: actions}
}

func TestHasApprovalBetweenBuildAndDeploy_NoApproval(t *testing.T) {
	stages := []cptypes.StageDeclaration{
		stage("Source", cptypes.ActionCategorySource),
		stage("Build", cptypes.ActionCategoryBuild),
		stage("Deploy", cptypes.ActionCategoryDeploy),
	}
	if hasApprovalBetweenBuildAndDeploy(stages) {
		t.Error("expected Source -> Build -> Deploy with no Approval stage to report no approval gate")
	}
}

func TestHasApprovalBetweenBuildAndDeploy_ApprovalBetween(t *testing.T) {
	stages := []cptypes.StageDeclaration{
		stage("Source", cptypes.ActionCategorySource),
		stage("Build", cptypes.ActionCategoryBuild),
		stage("Approval", cptypes.ActionCategoryApproval),
		stage("Deploy", cptypes.ActionCategoryDeploy),
	}
	if !hasApprovalBetweenBuildAndDeploy(stages) {
		t.Error("expected an Approval-category stage between Build and Deploy to satisfy the gate")
	}
}

func TestHasApprovalBetweenBuildAndDeploy_ApprovalInWrongPosition(t *testing.T) {
	// Approval before Build — does not gate the Build -> Deploy transition
	// at all, so this must still count as "no approval gate".
	stages := []cptypes.StageDeclaration{
		stage("Approval", cptypes.ActionCategoryApproval),
		stage("Source", cptypes.ActionCategorySource),
		stage("Build", cptypes.ActionCategoryBuild),
		stage("Deploy", cptypes.ActionCategoryDeploy),
	}
	if hasApprovalBetweenBuildAndDeploy(stages) {
		t.Error("expected an Approval stage positioned before Build (not between Build and Deploy) to NOT satisfy the gate")
	}
}

func TestHasApprovalBetweenBuildAndDeploy_ApprovalInsideDeployStage(t *testing.T) {
	// A real, valid layout: the approval action lives inside the same
	// stage as the deploy action, ordered ahead of it.
	stages := []cptypes.StageDeclaration{
		stage("Source", cptypes.ActionCategorySource),
		stage("Build", cptypes.ActionCategoryBuild),
		stage("Deploy", cptypes.ActionCategoryApproval, cptypes.ActionCategoryDeploy),
	}
	if !hasApprovalBetweenBuildAndDeploy(stages) {
		t.Error("expected an Approval action inside the Deploy stage, ordered before the Deploy action, to satisfy the gate")
	}
}

// ── name-correlation tie-break ────────────────────────────────────────────────
//
// matchAgentByName's fallback (longest-common-prefix + closest-length) had
// a real bug: two agents can share an identical, maximal common-prefix
// length with the search term when one name is a strict prefix of both —
// the fix must consistently prefer the closer overall length. Genericized
// names below reproduce the exact shape of the bug (a short "product-build"
// resource name that's a complete prefix of two differently-suffixed
// agent names) without using any real demo agent name.
func TestMatchAgentByName_EqualPrefixTieBreak(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "widgetfactory-notifier", StableID: "wrong-agent"},
		{Name: "WidgetFactory-Prod", StableID: "right-agent"},
	}

	got := matchAgentByName("widgetfactory-build", agents)
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.StableID != "right-agent" {
		t.Errorf("expected the closer-length match (WidgetFactory-Prod) to win the tie, got %q (%s)", got.Name, got.StableID)
	}
}

func TestMatchAgentByName_ExactMatchPreferred(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "widgetfactory-prod-worker", StableID: "prefix-match"},
		{Name: "widgetfactory", StableID: "exact-match"},
	}
	got := matchAgentByName("widgetfactory", agents)
	if got == nil || got.StableID != "exact-match" {
		t.Errorf("expected an exact normalized-name match to be preferred over any prefix match, got %+v", got)
	}
}

func TestMatchAgentByName_NoCandidateMeetsMinimumStem(t *testing.T) {
	agents := []types.CanonicalAgentRecord{
		{Name: "unrelated-service", StableID: "should-not-match"},
	}
	got := matchAgentByName("ab", agents)
	if got != nil {
		t.Errorf("expected no match for a search term shorter than the minimum stem length, got %+v", got)
	}
}

func TestMatchAgentByName_NoAgents(t *testing.T) {
	got := matchAgentByName("anything", nil)
	if got != nil {
		t.Errorf("expected nil when there are no candidate agents, got %+v", got)
	}
}
