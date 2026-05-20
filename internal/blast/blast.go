// Package blast implements blast radius computation (spec section 8.1).
package blast

import (
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// Compute calculates the blast radius for each agent and updates
// the agent's BlastRadius field in place.
func Compute(agents []types.CanonicalAgentRecord, edges []types.AgentEdgeRecord) []types.CanonicalAgentRecord {
	// Build reachability graph
	outEdges := make(map[string][]types.AgentEdgeRecord)
	for _, e := range edges {
		outEdges[e.SourceStableID] = append(outEdges[e.SourceStableID], e)
	}

	agentByID := make(map[string]*types.CanonicalAgentRecord, len(agents))
	for i := range agents {
		agentByID[agents[i].StableID] = &agents[i]
	}

	for i := range agents {
		agent := &agents[i]
		blast := computeBlast(agent, outEdges, agentByID)
		agent.BlastRadius = blast
	}

	return agents
}

func computeBlast(
	agent *types.CanonicalAgentRecord,
	outEdges map[string][]types.AgentEdgeRecord,
	agentByID map[string]*types.CanonicalAgentRecord,
) *types.BlastRadiusRecord {
	now := time.Now().UTC()

	// BFS to find all reachable agents (max 3 hops)
	visited := map[string]bool{agent.StableID: true}
	queue := []string{agent.StableID}
	var reachable []string
	var crossOrgEdges []string
	serviceSet := map[string]bool{}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, e := range outEdges[curr] {
			if visited[e.TargetStableID] {
				continue
			}
			visited[e.TargetStableID] = true
			reachable = append(reachable, e.TargetStableID)
			queue = append(queue, e.TargetStableID)

			if target, ok := agentByID[e.TargetStableID]; ok {
				if target.Platform != "" {
					serviceSet[target.Platform] = true
				}
				if target.OrgID != agent.OrgID && target.OrgID != "" {
					crossOrgEdges = append(crossOrgEdges, e.TargetStableID)
				}
			}
		}
	}

	// Compute permissions scope
	uniquePerms := len(agent.IAMPermissions)
	maxDataScope := computeDataScope(agent)

	// Score: base from permissions + reachability
	score := uniquePerms*5 + len(reachable)*10
	if agent.HasWildcard {
		score += 30
	}
	if len(crossOrgEdges) > 0 {
		score += 20
	}
	if score > 100 {
		score = 100
	}

	var tier types.RiskTier
	switch {
	case score >= 75:
		tier = types.RiskTierCritical
	case score >= 50:
		tier = types.RiskTierHigh
	case score >= 25:
		tier = types.RiskTierMedium
	default:
		tier = types.RiskTierLow
	}

	var services []string
	for svc := range serviceSet {
		services = append(services, svc)
	}

	return &types.BlastRadiusRecord{
		Tier:                  tier,
		Score:                 score,
		UniquePermissions:     uniquePerms,
		MaxDataScope:          maxDataScope,
		ReachableAgentIDs:     reachable,
		ReachableServices:     services,
		CrossOrgEdges:         crossOrgEdges,
		NormalizedPermissions: agent.IAMPermissions,
		ComputedAt:            now,
	}
}

func computeDataScope(agent *types.CanonicalAgentRecord) string {
	if agent.HasWildcard {
		return "ACCOUNT_WIDE"
	}

	services := map[string]bool{}
	for _, p := range agent.IAMPermissions {
		// Extract service from action (e.g., "s3:GetObject" → "s3")
		parts := splitColon(p.RawAction)
		if len(parts) == 2 {
			services[parts[0]] = true
		}
	}

	switch {
	case len(services) > 3:
		return "MULTI_SERVICE"
	case len(services) > 1:
		return "MULTI_SERVICE"
	case len(services) == 1:
		return "SINGLE_SERVICE"
	default:
		return "NARROW"
	}
}

func splitColon(s string) []string {
	for i, c := range s {
		if c == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
