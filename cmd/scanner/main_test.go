// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// TestDeduplicateFindings_DistinctUnresolvedDependenciesBothSurvive is the
// regression test for the exact bug found investigating
// DataPipeline-Orchestrator: two genuinely distinct AGENT_UNRESOLVED_DEPENDENCY
// findings for the same agent, each referencing a different target, were
// silently collapsing to one under the old (AgentStableID, RuleID)-only key.
func TestDeduplicateFindings_DistinctUnresolvedDependenciesBothSurvive(t *testing.T) {
	findings := []types.FindingRecord{
		{
			AgentStableID: "agent-1",
			RuleID:        "AGENT_UNRESOLVED_DEPENDENCY",
			EvidenceJSON:  []byte(`{"targetExternalId":"arn:aws:lambda:us-east-1:111111111111:function:example-known-target"}`),
		},
		{
			AgentStableID: "agent-1",
			RuleID:        "AGENT_UNRESOLVED_DEPENDENCY",
			EvidenceJSON:  []byte(`{"targetExternalId":"arn:aws:iam::111111111111:role/example-stale-role"}`),
		},
	}

	got := deduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected both distinct unresolved-dependency findings to survive, got %d: %+v", len(got), got)
	}
}

func TestDeduplicateFindings_SameTargetTrueDuplicateCollapses(t *testing.T) {
	findings := []types.FindingRecord{
		{
			AgentStableID: "agent-1",
			RuleID:        "AGENT_UNRESOLVED_DEPENDENCY",
			EvidenceJSON:  []byte(`{"targetExternalId":"arn:aws:lambda:us-east-1:111111111111:function:example-target"}`),
		},
		{
			AgentStableID: "agent-1",
			RuleID:        "AGENT_UNRESOLVED_DEPENDENCY",
			EvidenceJSON:  []byte(`{"targetExternalId":"arn:aws:lambda:us-east-1:111111111111:function:example-target"}`),
		},
	}

	got := deduplicateFindings(findings)
	if len(got) != 1 {
		t.Errorf("expected two findings with the identical target to collapse to 1, got %d", len(got))
	}
}

// TestDeduplicateFindings_MissingIntentDeclarationStillCollapses is the
// regression test protecting the dedup's original, explicitly-documented
// purpose: MISSING_INTENT_DECLARATION is emitted independently by both the
// AWS Bedrock intent check and staticref's generic intent check for the
// same agent, with genuinely different wording and evidence shapes.
// Widening the key for every rule (e.g. keying on Description) would have
// split this intentional collapse back apart.
func TestDeduplicateFindings_MissingIntentDeclarationStillCollapses(t *testing.T) {
	findings := []types.FindingRecord{
		{
			AgentStableID: "agent-1",
			RuleID:        "MISSING_INTENT_DECLARATION",
			Plugin:        "aws",
			Description:   "Bedrock agent example-agent has no declared intent. Add a specter:intent tag to the Bedrock agent resource.",
			EvidenceJSON:  []byte(`{"agentId":"example-agent-id","agentName":"example-agent","intentTagValue":""}`),
		},
		{
			AgentStableID: "agent-1",
			RuleID:        "MISSING_INTENT_DECLARATION",
			Plugin:        "staticref",
			Description:   "Agent example-agent has no formal intent file (.specter/manifest.yaml, AGENT.md, CLAUDE.md). A README description is not a sufficient governance declaration.",
			EvidenceJSON:  []byte(`{"agentName":"example-agent","platform":"AWS_BEDROCK","intentSource":"","visibilityClass":"SHADOW"}`),
		},
	}

	got := deduplicateFindings(findings)
	if len(got) != 1 {
		t.Errorf("expected the two independently-emitted MISSING_INTENT_DECLARATION findings for the same agent to still collapse to 1, got %d: %+v", len(got), got)
	}
}

func TestDeduplicateFindings_DifferentAgentsBothSurvive(t *testing.T) {
	findings := []types.FindingRecord{
		{AgentStableID: "agent-1", RuleID: "IAM_NO_OWNER_TAG"},
		{AgentStableID: "agent-2", RuleID: "IAM_NO_OWNER_TAG"},
	}
	got := deduplicateFindings(findings)
	if len(got) != 2 {
		t.Errorf("expected findings for two different agents to both survive, got %d", len(got))
	}
}

func TestDeduplicateFindings_UnresolvedDependencyMissingEvidenceFallsBackToCoarseKey(t *testing.T) {
	// No parseable targetExternalId in EvidenceJSON — the discriminator
	// can't distinguish them, so this falls back to the original
	// (AgentStableID, RuleID) behavior rather than erroring.
	findings := []types.FindingRecord{
		{AgentStableID: "agent-1", RuleID: "AGENT_UNRESOLVED_DEPENDENCY", EvidenceJSON: nil},
		{AgentStableID: "agent-1", RuleID: "AGENT_UNRESOLVED_DEPENDENCY", EvidenceJSON: []byte(`{}`)},
	}
	got := deduplicateFindings(findings)
	if len(got) != 1 {
		t.Errorf("expected findings with no distinguishing evidence to collapse via the coarse fallback key, got %d", len(got))
	}
}
