// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package staticref

import (
	"context"
	"testing"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ── resolveTarget ──────────────────────────────────────────────────────────────

func TestResolveTarget_ExternalIDExactMatch(t *testing.T) {
	target := &types.CanonicalAgentRecord{StableID: "target-agent", ExternalID: "arn:aws:lambda:us-east-1:111111111111:function:example-target"}
	byExternalID := map[string]*types.CanonicalAgentRecord{target.ExternalID: target}

	got := resolveTarget(target.ExternalID, byExternalID, nil, nil)
	if got == nil || got.StableID != "target-agent" {
		t.Errorf("expected exact ExternalID match to resolve, got %+v", got)
	}
}

func TestResolveTarget_PublicURLMatch(t *testing.T) {
	target := &types.CanonicalAgentRecord{StableID: "target-agent", PublicURL: "https://example.execute-api.us-east-1.amazonaws.com/"}
	byPublicURL := map[string]*types.CanonicalAgentRecord{normalizeURL(target.PublicURL): target}

	got := resolveTarget("https://EXAMPLE.execute-api.us-east-1.amazonaws.com", nil, byPublicURL, nil)
	if got == nil || got.StableID != "target-agent" {
		t.Errorf("expected a case/trailing-slash-normalized URL match to resolve, got %+v", got)
	}
}

// TestResolveTarget_IAMRoleARNExactMatch is the regression test for the
// resolveTarget blind spot found investigating why a real, scoped
// sts:AssumeRole grant on an already-known agent's own execution role
// never resolved into an edge: resolveTarget only checked ExternalID
// (always a function/service ARN) and PublicURL, never IAMRoleARN — the
// field an sts:AssumeRole ref's target always is.
func TestResolveTarget_IAMRoleARNExactMatch(t *testing.T) {
	target := &types.CanonicalAgentRecord{
		StableID:   "target-agent",
		ExternalID: "arn:aws:lambda:us-east-1:111111111111:function:example-target",
		IAMRoleARN: "arn:aws:iam::111111111111:role/example-target-execution-role",
	}
	byIAMRoleARN := map[string]*types.CanonicalAgentRecord{target.IAMRoleARN: target}

	got := resolveTarget(target.IAMRoleARN, nil, nil, byIAMRoleARN)
	if got == nil || got.StableID != "target-agent" {
		t.Errorf("expected an exact IAMRoleARN match to resolve, got %+v", got)
	}
}

func TestResolveTarget_IAMRoleARNDoesNotFuzzyMatch(t *testing.T) {
	// Two different roles that happen to share a naming prefix must not
	// cross-resolve — IAM role ARN matching is exact-only, unlike the
	// ExternalID/PublicURL paths' prefix/suffix fallback.
	target := &types.CanonicalAgentRecord{
		StableID:   "target-agent",
		IAMRoleARN: "arn:aws:iam::111111111111:role/example-role",
	}
	byIAMRoleARN := map[string]*types.CanonicalAgentRecord{target.IAMRoleARN: target}

	got := resolveTarget("arn:aws:iam::111111111111:role/example-role-v2", nil, nil, byIAMRoleARN)
	if got != nil {
		t.Errorf("expected no match for a role ARN that only shares a naming prefix, got %+v", got)
	}
}

func TestResolveTarget_ExternalIDPrefixMatchStillWorks(t *testing.T) {
	target := &types.CanonicalAgentRecord{StableID: "target-agent", ExternalID: "arn:aws:execute-api:us-east-1:111111111111:abc123"}
	byExternalID := map[string]*types.CanonicalAgentRecord{target.ExternalID: target}

	got := resolveTarget("arn:aws:execute-api:us-east-1:111111111111:abc123/prod/GET/resource", byExternalID, nil, nil)
	if got == nil || got.StableID != "target-agent" {
		t.Errorf("expected the pre-existing ExternalID prefix-match fallback to still resolve, got %+v", got)
	}
}

func TestResolveTarget_NoMatch(t *testing.T) {
	byExternalID := map[string]*types.CanonicalAgentRecord{"arn:aws:lambda:us-east-1:111111111111:function:known": {StableID: "known"}}
	byIAMRoleARN := map[string]*types.CanonicalAgentRecord{"arn:aws:iam::111111111111:role/known-role": {StableID: "known"}}

	got := resolveTarget("arn:aws:iam::111111111111:role/totally-unrelated-role", byExternalID, nil, byIAMRoleARN)
	if got != nil {
		t.Errorf("expected no match for an unrelated target, got %+v", got)
	}
}

// ── Analyze: end-to-end sts:AssumeRole edge resolution ──────────────────────────

// TestAnalyze_STSAssumeRoleResolvesAgainstKnownAgentRole reproduces, with
// genericized fixtures, the exact live shape found investigating
// DataPipeline-Orchestrator's real sts:AssumeRole grant on
// ReportGen-Nightly's role: a source agent has a scoped sts:AssumeRole
// StaticRef whose target is another already-known agent's own execution
// role ARN. This must now resolve into a real STS_ASSUME edge, not an
// AGENT_UNRESOLVED_DEPENDENCY finding.
func TestAnalyze_STSAssumeRoleResolvesAgainstKnownAgentRole(t *testing.T) {
	source := types.CanonicalAgentRecord{
		StableID:   "source-agent",
		Name:       "example-source-agent",
		ExternalID: "arn:aws:lambda:us-east-1:111111111111:function:example-source",
	}
	target := types.CanonicalAgentRecord{
		StableID:   "target-agent",
		Name:       "example-target-agent",
		ExternalID: "arn:aws:lambda:us-east-1:111111111111:function:example-target",
		IAMRoleARN: "arn:aws:iam::111111111111:role/example-target-execution-role",
	}
	refs := []types.StaticRef{
		{
			SourceAgentExternalID: source.ExternalID,
			TargetExternalID:      target.IAMRoleARN,
			RefSource:             "IAM_POLICY",
			EdgeType:              types.EdgeTypeSTSAssume,
			Confidence:            0.90,
			Evidence:              "IAM policy allows sts:AssumeRole on " + target.IAMRoleARN,
		},
	}

	analyzer := New("test-org")
	edges, findings := analyzer.Analyze(context.Background(), []types.CanonicalAgentRecord{source, target}, refs, nil)

	if len(edges) != 1 {
		t.Fatalf("expected 1 resolved edge, got %d (findings: %+v)", len(edges), findings)
	}
	if edges[0].SourceStableID != "source-agent" || edges[0].TargetStableID != "target-agent" {
		t.Errorf("expected edge source-agent -> target-agent, got %+v", edges[0])
	}
	if edges[0].EdgeType != types.EdgeTypeSTSAssume {
		t.Errorf("expected EdgeType=%q, got %q", types.EdgeTypeSTSAssume, edges[0].EdgeType)
	}
	for _, f := range findings {
		if f.RuleID == "AGENT_UNRESOLVED_DEPENDENCY" {
			t.Errorf("expected no AGENT_UNRESOLVED_DEPENDENCY finding now that the target resolves, got %+v", f)
		}
	}
}

func TestAnalyze_STSAssumeRoleUnresolvedWhenTargetUnknown(t *testing.T) {
	source := types.CanonicalAgentRecord{
		StableID:   "source-agent",
		Name:       "example-source-agent",
		ExternalID: "arn:aws:lambda:us-east-1:111111111111:function:example-source",
	}
	refs := []types.StaticRef{
		{
			SourceAgentExternalID: source.ExternalID,
			TargetExternalID:      "arn:aws:iam::111111111111:role/nonexistent-role",
			RefSource:             "IAM_POLICY",
			EdgeType:              types.EdgeTypeSTSAssume,
			Confidence:            0.90,
			Evidence:              "IAM policy allows sts:AssumeRole on arn:aws:iam::111111111111:role/nonexistent-role",
		},
	}

	analyzer := New("test-org")
	edges, findings := analyzer.Analyze(context.Background(), []types.CanonicalAgentRecord{source}, refs, nil)

	if len(edges) != 0 {
		t.Errorf("expected no edges when the target role belongs to no known agent, got %d", len(edges))
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "AGENT_UNRESOLVED_DEPENDENCY" {
			found = true
		}
	}
	if !found {
		t.Error("expected an AGENT_UNRESOLVED_DEPENDENCY finding for a genuinely unresolvable target")
	}
}
