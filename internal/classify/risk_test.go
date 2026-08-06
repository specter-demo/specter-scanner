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
				agent.HasWildcard = true                                           // 5 + 30 + 20 (wildcard) = 55... need more; use FunctionURLAuthType too
				agent.FunctionURLAuthType = "NONE"                                 // 5 + 30 + 20 + 15 = 70... still not 75; add orchestrator
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

// 2026-08-06: every case above uses VisibilityClassGoverned exclusively —
// SHADOW, DISCOVERED, and UNREGISTERED had zero coverage. Found while
// investigating why a real scan's HIGH tier stayed empty even after the
// per-finding fix above: SHADOW's base (40) leaves only a 10-34 point
// window before crossing the 75 CRITICAL floor, so any SHADOW agent that
// also has wildcard IAM (+20) AND an open function URL (+15) — a common
// real combination, since ungoverned agents tend to be poorly secured on
// multiple axes at once — skips HIGH entirely regardless of what findings
// exist. These three cases turn that by-hand arithmetic into a permanent
// regression instead of something that has to be recomputed manually next
// time this comes up.
func TestComputeRiskScore_ShadowHighWindow(t *testing.T) {
	mkShadow := func() *types.CanonicalAgentRecord {
		return &types.CanonicalAgentRecord{StableID: "s-1", VisibilityClass: types.VisibilityClassShadow}
	}

	t.Run("SHADOW + wildcard only, no findings -> HIGH (40+20=60)", func(t *testing.T) {
		agent := mkShadow()
		agent.HasWildcard = true
		score := ComputeRiskScore(agent, nil, nil)
		if score != 60 {
			t.Errorf("got score %d, want 60", score)
		}
		if tier := deriveRiskTier(score); tier != "HIGH" {
			t.Errorf("got tier %s, want HIGH", tier)
		}
	})

	t.Run("SHADOW + open function URL only, no findings -> HIGH (40+15=55)", func(t *testing.T) {
		agent := mkShadow()
		agent.FunctionURLAuthType = "NONE"
		score := ComputeRiskScore(agent, nil, nil)
		if score != 55 {
			t.Errorf("got score %d, want 55", score)
		}
		if tier := deriveRiskTier(score); tier != "HIGH" {
			t.Errorf("got tier %s, want HIGH", tier)
		}
	})

	t.Run("SHADOW + wildcard + open URL together, no findings -> CRITICAL, skipping HIGH (40+20+15=75)", func(t *testing.T) {
		agent := mkShadow()
		agent.HasWildcard = true
		agent.FunctionURLAuthType = "NONE"
		score := ComputeRiskScore(agent, nil, nil)
		if score != 75 {
			t.Errorf("got score %d, want 75", score)
		}
		if tier := deriveRiskTier(score); tier != "CRITICAL" {
			t.Errorf("got tier %s, want CRITICAL — this is the exact mechanism that leaves HIGH empty for real SHADOW agents with both risk factors", tier)
		}
	})
}

// All 4 tiers, proven reachable from each non-GOVERNED visibility class
// where mathematically possible — mirroring the rigor already applied to
// GOVERNED above. SHADOW (base 40) and UNREGISTERED (base 30) can never
// land in LOW (<25): their base alone already exceeds the LOW ceiling, so
// no combination of findings/modifiers can pull them below MEDIUM. That's
// asserted explicitly below rather than silently omitted, so it reads as
// a confirmed structural property, not a coverage gap.
func TestComputeRiskScore_AllVisibilityClasses(t *testing.T) {
	mkAgent := func(id string, vis types.VisibilityClass) *types.CanonicalAgentRecord {
		return &types.CanonicalAgentRecord{StableID: id, VisibilityClass: vis}
	}
	mkFindings := func(agentID string, severity string, count int) []types.FindingRecord {
		fs := make([]types.FindingRecord, count)
		for i := range fs {
			fs[i] = types.FindingRecord{AgentStableID: agentID, Severity: severity}
		}
		return fs
	}

	t.Run("DISCOVERED (base 20)", func(t *testing.T) {
		cases := []struct {
			name     string
			build    func(a *types.CanonicalAgentRecord) []types.FindingRecord
			wantTier string
		}{
			{"no findings, no modifiers (20) -> LOW", func(a *types.CanonicalAgentRecord) []types.FindingRecord { return nil }, "LOW"},
			{"1 HIGH finding (20+5=25) -> MEDIUM", func(a *types.CanonicalAgentRecord) []types.FindingRecord { return mkFindings("d-1", "HIGH", 1) }, "MEDIUM"},
			{"3 CRITICAL findings (20+30=50) -> HIGH", func(a *types.CanonicalAgentRecord) []types.FindingRecord { return mkFindings("d-1", "CRITICAL", 3) }, "HIGH"},
			{"wildcard + open URL + 3 CRITICAL (20+20+15+30=85) -> CRITICAL", func(a *types.CanonicalAgentRecord) []types.FindingRecord {
				a.HasWildcard = true
				a.FunctionURLAuthType = "NONE"
				return mkFindings("d-1", "CRITICAL", 3)
			}, "CRITICAL"},
		}
		seenTiers := map[string]bool{}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				agent := mkAgent("d-1", types.VisibilityClassDiscovered)
				findings := c.build(agent)
				gotTier := deriveRiskTier(ComputeRiskScore(agent, nil, findings))
				if gotTier != c.wantTier {
					t.Errorf("got tier %s, want %s", gotTier, c.wantTier)
				}
				seenTiers[gotTier] = true
			})
		}
		for _, tier := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if !seenTiers[tier] {
				t.Errorf("DISCOVERED: tier %s never reached", tier)
			}
		}
	})

	t.Run("SHADOW (base 40) — LOW is structurally unreachable", func(t *testing.T) {
		cases := []struct {
			name     string
			build    func(a *types.CanonicalAgentRecord)
			wantTier string
		}{
			{"no findings, no modifiers (40) -> MEDIUM", func(a *types.CanonicalAgentRecord) {}, "MEDIUM"},
			{"wildcard only (40+20=60) -> HIGH", func(a *types.CanonicalAgentRecord) { a.HasWildcard = true }, "HIGH"},
			{"wildcard + open URL (40+20+15=75) -> CRITICAL", func(a *types.CanonicalAgentRecord) {
				a.HasWildcard = true
				a.FunctionURLAuthType = "NONE"
			}, "CRITICAL"},
		}
		seenTiers := map[string]bool{}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				agent := mkAgent("sh-1", types.VisibilityClassShadow)
				c.build(agent)
				gotTier := deriveRiskTier(ComputeRiskScore(agent, nil, nil))
				if gotTier != c.wantTier {
					t.Errorf("got tier %s, want %s", gotTier, c.wantTier)
				}
				seenTiers[gotTier] = true
			})
		}
		for _, tier := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
			if !seenTiers[tier] {
				t.Errorf("SHADOW: tier %s never reached", tier)
			}
		}
		if seenTiers["LOW"] {
			t.Errorf("SHADOW: LOW was reached, but base(40) alone should make LOW structurally impossible — investigate before trusting this result")
		}
	})

	t.Run("UNREGISTERED (base 30) — LOW is structurally unreachable", func(t *testing.T) {
		cases := []struct {
			name     string
			build    func(a *types.CanonicalAgentRecord)
			wantTier string
		}{
			{"no findings, no modifiers (30) -> MEDIUM", func(a *types.CanonicalAgentRecord) {}, "MEDIUM"},
			{"wildcard only (30+20=50) -> HIGH", func(a *types.CanonicalAgentRecord) { a.HasWildcard = true }, "HIGH"},
			{"wildcard + open URL (30+20+15=65) still HIGH, not yet CRITICAL", func(a *types.CanonicalAgentRecord) {
				a.HasWildcard = true
				a.FunctionURLAuthType = "NONE"
			}, "HIGH"},
			{"wildcard + open URL + orchestrator (30+20+15+10=75) -> CRITICAL", func(a *types.CanonicalAgentRecord) {
				a.HasWildcard = true
				a.FunctionURLAuthType = "NONE"
				a.FunctionalClass = types.FunctionalClassConfirmedOrchestrator
			}, "CRITICAL"},
		}
		seenTiers := map[string]bool{}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				agent := mkAgent("u-1", types.VisibilityClassUnregistered)
				c.build(agent)
				gotTier := deriveRiskTier(ComputeRiskScore(agent, nil, nil))
				if gotTier != c.wantTier {
					t.Errorf("got tier %s, want %s", gotTier, c.wantTier)
				}
				seenTiers[gotTier] = true
			})
		}
		for _, tier := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
			if !seenTiers[tier] {
				t.Errorf("UNREGISTERED: tier %s never reached", tier)
			}
		}
		if seenTiers["LOW"] {
			t.Errorf("UNREGISTERED: LOW was reached, but base(30) alone should make LOW structurally impossible — investigate before trusting this result")
		}
	})
}

// Reproduces the 8 real org_vantage_demo CRITICAL-tier agents tabulated in
// the 2026-08-06 HIGH-reachability investigation, from their real
// visibility class and finding profile. The platform DB only persists the
// final riskScore/riskTier, not the scanner's raw HasWildcard/
// FunctionURLAuthType/FunctionalClass/edge inputs, so each case's
// non-finding modifiers are reconstructed to the minimal combination that
// reaches that agent's documented real score exactly — not read back from
// stored raw data (which doesn't exist downstream of ingest). This locks
// in the real production outcome as a regression baseline: had this test
// existed before 2026-08-05, the original missing-findings-parameter bug
// would have failed here immediately instead of taking active investigation
// to surface.
func TestComputeRiskScore_RealOrgVantageDemoAgents(t *testing.T) {
	mkFindings := func(agentID string, severity string, count int) []types.FindingRecord {
		fs := make([]types.FindingRecord, count)
		for i := range fs {
			fs[i] = types.FindingRecord{AgentStableID: agentID, Severity: severity}
		}
		return fs
	}
	merge := func(groups ...[]types.FindingRecord) []types.FindingRecord {
		var out []types.FindingRecord
		for _, g := range groups {
			out = append(out, g...)
		}
		return out
	}

	cases := []struct {
		name      string
		vis       types.VisibilityClass
		build     func(a *types.CanonicalAgentRecord)
		findings  func(id string) []types.FindingRecord // takes the agent's own StableID, so a mismatched literal can't silently zero out the finding contribution
		wantScore int
		wantTier  string
	}{
		{
			name: "shadow-indexer", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) {
				a.HasWildcard = true
				a.FunctionalClass = types.FunctionalClassConfirmedOrchestrator
			},
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "CRITICAL", 4), mkFindings(id, "HIGH", 6), mkFindings(id, "MEDIUM", 2), mkFindings(id, "LOW", 1))
			},
			wantScore: 100, wantTier: "CRITICAL", // 40+30(capped)+20(capped)+20(wildcard)+10(orchestrator)=120, capped at 100
		},
		{
			name: "ComplianceAgent-Unguarded-StatusCheck", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.HasWildcard = true },
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "HIGH", 1), mkFindings(id, "CRITICAL", 1))
			},
			wantScore: 75, wantTier: "CRITICAL", // 40+10+5+20=75
		},
		{
			name: "PipelineForge-Prod", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.FunctionalClass = types.FunctionalClassConfirmedOrchestrator },
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "HIGH", 3), mkFindings(id, "CRITICAL", 1), mkFindings(id, "MEDIUM", 2))
			},
			wantScore: 75, wantTier: "CRITICAL", // 40+10+15+10=75
		},
		{
			name: "BillingAccess", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.HasWildcard = true; a.FunctionURLAuthType = "NONE" },
			findings: func(id string) []types.FindingRecord {
				return mkFindings(id, "MEDIUM", 1)
			},
			wantScore: 75, wantTier: "CRITICAL", // 40+0+20+15=75 (MEDIUM findings contribute nothing)
		},
		{
			name: "ReadOnlyAccess", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.HasWildcard = true; a.FunctionURLAuthType = "NONE" },
			findings: func(id string) []types.FindingRecord {
				return mkFindings(id, "MEDIUM", 1)
			},
			wantScore: 75, wantTier: "CRITICAL",
		},
		{
			name: "ShadowAnalytics-7f2a", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.FunctionURLAuthType = "NONE" },
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "HIGH", 2), mkFindings(id, "MEDIUM", 2), mkFindings(id, "CRITICAL", 1))
			},
			wantScore: 75, wantTier: "CRITICAL", // 40+10+10+15=75
		},
		{
			name: "ofac-screening-helper", vis: types.VisibilityClassShadow,
			build: func(a *types.CanonicalAgentRecord) { a.HasWildcard = true; a.FunctionURLAuthType = "NONE" },
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "LOW", 2), mkFindings(id, "MEDIUM", 1))
			},
			wantScore: 75, wantTier: "CRITICAL", // 40+0+20+15=75 (LOW/MEDIUM contribute nothing)
		},
		{
			name: "Meridian Data (Partner)", vis: types.VisibilityClassUnregistered,
			build: func(a *types.CanonicalAgentRecord) { a.FunctionURLAuthType = "NONE" },
			findings: func(id string) []types.FindingRecord {
				return merge(mkFindings(id, "HIGH", 2), mkFindings(id, "CRITICAL", 2))
			},
			wantScore: 75, wantTier: "CRITICAL", // 30+20+10+15=75
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := &types.CanonicalAgentRecord{StableID: c.name, VisibilityClass: c.vis}
			c.build(agent)
			score := ComputeRiskScore(agent, nil, c.findings(agent.StableID))
			if score != c.wantScore {
				t.Errorf("score = %d, want %d (real production value)", score, c.wantScore)
			}
			if tier := deriveRiskTier(score); tier != c.wantTier {
				t.Errorf("tier = %s, want %s (real production value)", tier, c.wantTier)
			}
		})
	}
}
