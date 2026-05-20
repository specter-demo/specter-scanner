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
func ComputeRiskScore(agent *types.CanonicalAgentRecord, edges []types.AgentEdgeRecord) int {
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
