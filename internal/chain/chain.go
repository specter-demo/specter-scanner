// Package chain implements causal delegation chain reconstruction (spec section 7.1).
// MVP: max 2 hops.
package chain

import (
	"time"

	"github.com/google/uuid"

	"github.com/specter-demo/specter-scanner/internal/types"
)

const maxHops = 2

// Reconstruct builds delegation chains from agent edges and events.
// It returns a slice of DelegationChainRecord (one per root agent).
func Reconstruct(
	agents []types.CanonicalAgentRecord,
	edges []types.AgentEdgeRecord,
	events []types.NormalizedEvent,
) []types.DelegationChainRecord {
	now := time.Now().UTC()
	agentByID := make(map[string]*types.CanonicalAgentRecord, len(agents))
	for i := range agents {
		agentByID[agents[i].StableID] = &agents[i]
	}

	// Build adjacency list: sourceID → []edges
	outEdges := make(map[string][]types.AgentEdgeRecord)
	for _, e := range edges {
		outEdges[e.SourceStableID] = append(outEdges[e.SourceStableID], e)
	}

	// Build inbound map: targetID → sourceIDs
	inEdges := make(map[string][]string)
	for _, e := range edges {
		inEdges[e.TargetStableID] = append(inEdges[e.TargetStableID], e.SourceStableID)
	}

	// Find root agents: agents with no inbound edges or with a SCHEDULER principal
	var chains []types.DelegationChainRecord
	for _, agent := range agents {
		// A root is an agent that has outbound edges but no inbound edges
		if len(inEdges[agent.StableID]) > 0 {
			continue
		}
		if len(outEdges[agent.StableID]) == 0 {
			continue
		}

		chain := buildChain(&agent, outEdges, agentByID, events, now)
		if len(chain.Hops) > 0 {
			chains = append(chains, chain)
		}
	}

	return chains
}

func buildChain(
	root *types.CanonicalAgentRecord,
	outEdges map[string][]types.AgentEdgeRecord,
	agentByID map[string]*types.CanonicalAgentRecord,
	events []types.NormalizedEvent,
	now time.Time,
) types.DelegationChainRecord {
	chainID := uuid.New().String()

	chain := types.DelegationChainRecord{
		ChainID:           chainID,
		RootAgentStableID: root.StableID,
		RootPrincipalType: string(root.FunctionalClass),
		RootIntent:        "unknown",
		ReconstructedAt:   now,
	}

	// Check if unattended (scheduler-triggered)
	for _, e := range events {
		if e.Principal.Type == "SCHEDULER" && e.Principal.ID != "" {
			chain.IsUnattended = true
			break
		}
	}

	// BFS up to maxHops
	visited := map[string]bool{root.StableID: true}
	queue := []struct {
		agentID string
		depth   int
	}{{root.StableID, 0}}

	var rfc8693Breaks []int

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.depth >= maxHops {
			continue
		}

		for _, edge := range outEdges[curr.agentID] {
			if visited[edge.TargetStableID] {
				continue
			}
			visited[edge.TargetStableID] = true

			hop := types.DelegationHop{
				AgentStableID: edge.TargetStableID,
				EdgeType:      edge.EdgeType,
				RFC8693:       edge.EdgeType == types.EdgeTypeSTSAssume,
			}

			// Check RFC8693 presence from events
			for _, ev := range events {
				if ev.RFC8693Present && ev.AssumedRoleARN != "" {
					if target, ok := agentByID[edge.TargetStableID]; ok {
						if target.IAMRoleARN == ev.AssumedRoleARN {
							hop.RFC8693 = true
						}
					}
				}
			}

			if !hop.RFC8693 && len(chain.Hops) > 0 {
				breakIdx := len(chain.Hops)
				rfc8693Breaks = append(rfc8693Breaks, breakIdx)
			}

			chain.Hops = append(chain.Hops, hop)
			queue = append(queue, struct {
				agentID string
				depth   int
			}{edge.TargetStableID, curr.depth + 1})
		}
	}

	// RFC8693 compliance: all hops must have RFC8693 = true
	allRFC8693 := true
	for _, hop := range chain.Hops {
		if !hop.RFC8693 {
			allRFC8693 = false
			break
		}
	}
	chain.RFC8693Compliant = allRFC8693

	if len(rfc8693Breaks) > 0 {
		breakAt := rfc8693Breaks[0]
		chain.ChainBreakAt = &breakAt
	}

	// Reconstruction confidence based on hop count and evidence
	switch len(chain.Hops) {
	case 0:
		chain.ReconstructionConfidence = 0
	case 1:
		chain.ReconstructionConfidence = 0.85
	default:
		chain.ReconstructionConfidence = 0.70
	}

	if len(chain.Hops) > maxHops {
		chain.PartialChain = true
	}

	return chain
}
