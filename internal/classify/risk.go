// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"github.com/specter-demo/specter-scanner/internal/types"
)

// ComputeRiskScore computes a 0–100 risk score for an agent (spec section 6.5).
//
// Base score from visibility:
//   SHADOW       → 40
//   DISCOVERED   → 20
//   GOVERNED     → 5
//   UNREGISTERED → 30
//
// Modifiers:
//   +20 if HasWildcard (IAM wildcard permissions)
//   +15 if FunctionURLAuthType == "NONE"
//   +10 per CRITICAL finding (capped at +30)
//   +5  per HIGH finding (capped at +20)
//   +10 if CONFIRMED_ORCHESTRATOR
//   +5  if LIKELY_ORCHESTRATOR
//   +10 if cross-org edge exists
//   +5  per outbound ENV_URL edge (capped at +15)
//
// Fixed 2026-08-05: the per-finding modifiers above were documented here
// but never implemented — this function didn't even take a findings
// parameter, so an agent's actual CRITICAL/HIGH finding count had zero
// effect on its score. In practice this meant risk tiers could only ever
// land at CRITICAL (via the SHADOW+wildcard+open-URL combination summing
// to exactly 75) or LOW (govern/discovered base with few modifiers) —
// HIGH (50-74) and MEDIUM (25-49) were structurally unreachable for any
// agent whose risk was actually driven by its findings, which is the
// normal case. Confirmed live: org_vantage_demo had 12 OPEN HIGH findings
// and 14 OPEN MEDIUM findings across its 12 agents, yet zero agents in
// either tier — this is that bug, not a coincidence.
func ComputeRiskScore(agent *types.CanonicalAgentRecord, edges []types.AgentEdgeRecord, findings []types.FindingRecord) int {
	score := 0

	// Base from visibility
	switch agent.VisibilityClass {
	case types.VisibilityClassShadow:
		score += 40
	case types.VisibilityClassDiscovered:
		score += 20
	case types.VisibilityClassGoverned:
		score += 5
	case types.VisibilityClassUnregistered:
		score += 30
	default:
		score += 20
	}

	// IAM wildcard permissions
	if agent.HasWildcard {
		score += 20
	}

	// Public function URL with no auth
	if agent.FunctionURLAuthType == "NONE" {
		score += 15
	}

	// Per-finding severity modifiers — counts only this agent's own
	// findings (matched by StableID), each capped independently.
	var criticalFindings, highFindings int
	for _, f := range findings {
		if f.AgentStableID != agent.StableID {
			continue
		}
		switch f.Severity {
		case "CRITICAL":
			criticalFindings++
		case "HIGH":
			highFindings++
		}
	}
	if add := criticalFindings * 10; add > 30 {
		score += 30
	} else {
		score += add
	}
	if add := highFindings * 5; add > 20 {
		score += 20
	} else {
		score += add
	}

	// Orchestrator bonus
	switch agent.FunctionalClass {
	case types.FunctionalClassConfirmedOrchestrator:
		score += 10
	case types.FunctionalClassLikelyOrchestrator:
		score += 5
	}

	// Edge-based modifiers
	var envURLEdges int
	for _, e := range edges {
		if e.SourceStableID != agent.StableID {
			continue
		}
		if e.EdgeType == types.EdgeTypeEnvURL {
			envURLEdges++
		}
		if e.EdgeType == types.EdgeTypeA2ACall || e.EdgeType == types.EdgeTypePartnerAgent {
			score += 10
		}
	}
	if envURLEdges > 0 {
		add := envURLEdges * 5
		if add > 15 {
			add = 15
		}
		score += add
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
