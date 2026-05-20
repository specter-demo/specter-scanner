package classify

import (
	"github.com/specter-demo/specter-scanner/internal/types"
)

// ClassifyFunctional determines the functional class of an agent based on
// its edge degrees (spec section 6.3).
//
// Rules:
// - MCP_SERVER: already set, preserved
// - If outDegree >= 2: CONFIRMED_ORCHESTRATOR
// - If outDegree == 1: LIKELY_ORCHESTRATOR
// - If inDegree > 0 and outDegree == 0: WORKER
// - If agent.IsEphemeral: EPHEMERAL
// - Default: WORKER
func ClassifyFunctional(agent *types.CanonicalAgentRecord, edges []types.AgentEdgeRecord) types.FunctionalClass {
	// Preserve explicit MCP_SERVER classification
	if agent.FunctionalClass == types.FunctionalClassMCPServer {
		return types.FunctionalClassMCPServer
	}

	// Preserve ephemeral
	if agent.IsEphemeral {
		return types.FunctionalClassEphemeral
	}

	var outDegree, inDegree int
	for _, e := range edges {
		if e.SourceStableID == agent.StableID {
			outDegree++
		}
		if e.TargetStableID == agent.StableID {
			inDegree++
		}
	}

	switch {
	case outDegree >= 2:
		return types.FunctionalClassConfirmedOrchestrator
	case outDegree == 1:
		return types.FunctionalClassLikelyOrchestrator
	case inDegree > 0 && outDegree == 0:
		return types.FunctionalClassWorker
	default:
		return types.FunctionalClassWorker
	}
}
