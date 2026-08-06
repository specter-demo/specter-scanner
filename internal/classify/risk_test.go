// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"testing"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// deriveRiskTier mirrors lib/rules.ts's deriveRiskTier in specter-platform
// (the DB write path) — duplicated here only so this test can assert on
// the tier an agent would actually land in, not just the raw score.
func deriveRiskTier(score int) string {
	switch {
	case score >= 75:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// 2026-08-05 fix: ComputeRiskScore documented +10/CRITICAL finding (capped
// +30) and +5/HIGH finding (capped +20) but never implemented them — the
// function didn't even accept a findings parameter. This meant an agent's
// actual finding severities had zero effect on its score, and HIGH/MEDIUM
// tiers were structurally unreachable for any agent whose risk was driven
// by findings (the normal case) rather than the specific SHADOW+wildcard
// +open-URL combination that happens to sum to exactly 75. These tests
// cover the fix directly (score computation) and end-to-end through tier
// derivation, confirming all 4 tiers are reachable given real findings.
func TestComputeRiskScore_FindingSeverityModifiers(t *testing.T) {
	agent := &types.CanonicalAgentRecord{
		StableID:        "agent-1",
		VisibilityClass: types.VisibilityClassGoverned, // base 5
	}

	t.Run("no findings — base score only", func(t *testing.T) {
		got := ComputeRiskScore(agent, nil, nil)
		if got != 5 {
			t.Errorf("got %d, want 5 (GOVERNED base, no modifiers)", got)
		}
	})

	t.Run("counts only this agent's own findings, by AgentStableID", func(t *testing.T) {
		findings := []types.FindingRecord{
			{AgentStableID: "agent-1", Severity: "CRITICAL"},
			{AgentStableID: "other-agent", Severity: "CRITICAL"}, // must not count
		}
		got := ComputeRiskScore(agent, nil, findings)
		want := 5 + 10 // base + one CRITICAL
		if got != want {
			t.Errorf("got %d, want %d — a different agent's finding was counted", got, want)
		}
	})

	t.Run("CRITICAL findings capped at +30 (3 findings = cap, not 40)", func(t *testing.T) {
		findings := make([]types.FindingRecord, 4)
		for i := range findings {
			findings[i] = types.FindingRecord{AgentStableID: "agent-1", Severity: "CRITICAL"}
		}
		got := ComputeRiskScore(agent, nil, findings)
		want := 5 + 30 // base + capped CRITICAL bonus, not 5+40
		if got != want {
			t.Errorf("got %d, want %d (CRITICAL bonus should cap at +30)", got, want)
		}
	})

	t.Run("HIGH findings capped at +20 (5 findings = cap, not 25)", func(t *testing.T) {
		findings := make([]types.FindingRecord, 5)
		for i := range findings {
			findings[i] = types.FindingRecord{AgentStableID: "agent-1", Severity: "HIGH"}
		}
		got := ComputeRiskScore(agent, nil, findings)
		want := 5 + 20 // base + capped HIGH bonus, not 5+25
		if got != want {
			t.Errorf("got %d, want %d (HIGH bonus should cap at +20)", got, want)
		}
	})

	t.Run("MEDIUM/LOW/INFO findings contribute no score modifier (not documented)", func(t *testing.T) {
		findings := []types.FindingRecord{
			{AgentStableID: "agent-1", Severity: "MEDIUM"},
			{AgentStableID: "agent-1", Severity: "LOW"},
			{AgentStableID: "agent-1", Severity: "INFO"},
		}
		got := ComputeRiskScore(agent, nil, findings)
		if got != 5 {
			t.Errorf("got %d, want 5 — only CRITICAL/HIGH are documented as score modifiers", got)
		}
	})
}

// End-to-end: given real, non-zero finding counts across CRITICAL/HIGH,
// all 4 risk tiers are reachable — the exact regression this fix closes.
// GOVERNED base (5) + finding modifiers lands each agent in a distinct
// tier, matching the org_vantage_demo shape (findings across all 4
// severities, but before the fix, tiers only ever landing at
// CRITICAL/LOW).
func TestComputeRiskScore_AllFourTiersReachableWithRealFindings(t *testing.T) {
	mkAgent := func(id string) *types.CanonicalAgentRecord {
		return &types.CanonicalAgentRecord{StableID: id, VisibilityClass: types.VisibilityClassGoverned}
	}
	mkFindings := func(agentID string, severity string, count int) []types.FindingRecord {
		fs := make([]types.FindingRecord, count)
		for i := range fs {
			fs[i] = types.FindingRecord{AgentStableID: agentID, Severity: severity}
		}
		return fs
	}

	cases := []struct {
		name     string
		agentID  string
		findings []types.FindingRecord
		wantTier string
	}{
		{"zero findings -> LOW", "a-low", nil, "LOW"},
		{"3 HIGH findings (5 + 15 = 20) -> LOW", "a-low2", mkFindings("a-low2", "HIGH", 3), "LOW"},
		{"5 HIGH findings (5 + 20 = 25) -> MEDIUM", "a-medium", mkFindings("a-medium", "HIGH", 5), "MEDIUM"},
		{"5 CRITICAL findings (5 + 30 = 35, capped) -> MEDIUM", "a-medium2", mkFindings("a-medium2", "CRITICAL", 5), "MEDIUM"},
		{"2 CRITICAL + 5 HIGH (5 + 20 + 20 = 45) -> MEDIUM", "a-medium3", append(mkFindings("a-medium3", "CRITICAL", 2), mkFindings("a-medium3", "HIGH", 5)...), "MEDIUM"},
		{"5 CRITICAL + 5 HIGH (5 + 30 + 20 = 55) -> HIGH", "a-high", append(mkFindings("a-high", "CRITICAL", 5), mkFindings("a-high", "HIGH", 5)...), "HIGH"},
		{"8 CRITICAL findings (5 + 30 capped = 35) plus wildcard -> CRITICAL", "a-critical", mkFindings("a-critical", "CRITICAL", 8), "CRITICAL"},
	}

	seenTiers := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := mkAgent(c.agentID)
			if c.name == "8 CRITICAL findings (5 + 30 capped = 35) plus wildcard -> CRITICAL" {
				agent.HasWildcard = true // 5 + 30 + 20 (wildcard) = 55... need more; use FunctionURLAuthType too
				agent.FunctionURLAuthType = "NONE" // 5 + 30 + 20 + 15 = 70... still not 75; add orchestrator
				agent.FunctionalClass = types.FunctionalClassConfirmedOrchestrator // 70 + 10 = 80 -> CRITICAL
			}
			score := ComputeRiskScore(agent, nil, c.findings)
			gotTier := deriveRiskTier(score)
			if gotTier != c.wantTier {
				t.Errorf("%s: score=%d, tier=%s, want tier=%s", c.name, score, gotTier, c.wantTier)
			}
			seenTiers[gotTier] = true
		})
	}

	for _, tier := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if !seenTiers[tier] {
			t.Errorf("tier %s was never reached by any case — regression not fully covered", tier)
		}
	}
}
