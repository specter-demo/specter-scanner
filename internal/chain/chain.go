// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
//
// confirmedHumanPrincipals optionally maps a principal ID (e.g. an
// assumed-role ARN) to true when a platform-specific authoritative source
// (AWS IAM Identity Center, for the AWS plugin) has confirmed that
// principal is human — overriding hasHumanPrincipal's own CloudTrail-based
// inference for that specific principal. A nil map (or a principal absent
// from it) falls back to CloudTrail inference entirely; this must never be
// used to assert a principal is NOT human, only to confirm when it is.
func Reconstruct(
	agents []types.CanonicalAgentRecord,
	edges []types.AgentEdgeRecord,
	events []types.NormalizedEvent,
	confirmedHumanPrincipals map[string]bool,
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

		chain := buildChain(&agent, outEdges, agentByID, events, confirmedHumanPrincipals, now)
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
	confirmedHumanPrincipals map[string]bool,
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

	// Unattended detection. Primary signal: direct enumeration (e.g. an
	// EventBridge rule whose target is this root agent) has already
	// authoritatively confirmed a human-approval-free trigger — see
	// CanonicalAgentRecord.UnattendedTriggerConfirmed. Otherwise, per spec
	// §7.1: IsUnattended = !hasHumanPrincipal(chain), computed only over
	// this chain's own agents (root + hops), not a global scan across
	// every event in the scan.
	//
	// Note the resulting bias, matching spec's own definition: absence of
	// observed human involvement is treated as unattended, not as
	// "unknown" — the same conservative-toward-flagging default the old
	// global SCHEDULER-only check did not have.
	if root.UnattendedTriggerConfirmed {
		chain.IsUnattended = true
	} else {
		chainAgents := make([]*types.CanonicalAgentRecord, 0, len(chain.Hops)+1)
		chainAgents = append(chainAgents, root)
		for _, hop := range chain.Hops {
			if a, ok := agentByID[hop.AgentStableID]; ok {
				chainAgents = append(chainAgents, a)
			}
		}
		chain.IsUnattended = !hasHumanPrincipal(chainAgents, events, confirmedHumanPrincipals)
	}

	return chain
}

// hasHumanPrincipal reports whether a human principal is present anywhere
// in this specific chain (root + hops) — chain-scoped, per spec §7.1,
// rather than the account-wide scan the old SCHEDULER-only check did. For
// each event whose AssumedRoleARN matches one of the chain's agents' IAM
// role ARNs (the same AssumedRoleARN-to-agent.IAMRoleARN correlation
// already used for RFC8693 hop detection above), the principal is checked
// against confirmedHumanPrincipals first — an authoritative source (IAM
// Identity Center, for AWS) that overrides the CloudTrail-inferred
// Principal.Type when it can conclusively confirm a principal is human —
// falling back to Principal.Type == "HUMAN" (extractPrincipal's own
// classification) when confirmedHumanPrincipals has no entry for it.
func hasHumanPrincipal(chainAgents []*types.CanonicalAgentRecord, events []types.NormalizedEvent, confirmedHumanPrincipals map[string]bool) bool {
	roleARNs := make(map[string]bool, len(chainAgents))
	for _, a := range chainAgents {
		if a != nil && a.IAMRoleARN != "" {
			roleARNs[a.IAMRoleARN] = true
		}
	}
	if len(roleARNs) == 0 {
		return false
	}

	for _, e := range events {
		if e.AssumedRoleARN == "" || !roleARNs[e.AssumedRoleARN] {
			continue
		}
		if isHuman, resolved := confirmedHumanPrincipals[e.Principal.ID]; resolved {
			if isHuman {
				return true
			}
			continue
		}
		if e.Principal.Type == "HUMAN" {
			return true
		}
	}
	return false
}
