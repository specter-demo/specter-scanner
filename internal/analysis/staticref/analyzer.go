// Package staticref implements the static reference analyser (Phase 11.5).
//
// It resolves statically-discovered references (env vars, IAM policies, source
// code) against the known agent registry to produce AgentEdgeRecords and
// security findings.
package staticref

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// Analyzer resolves static references and produces edges and findings.
type Analyzer struct {
	orgID string
}

// New creates a new StaticReferenceAnalyzer for the given org.
func New(orgID string) *Analyzer {
	return &Analyzer{orgID: orgID}
}

// Analyze processes the collected static refs against the discovered agents,
// creates resolved edges, and emits findings for unresolved high-confidence
// references and intent mismatches.
//
// existingEdges is used to deduplicate against already-known runtime edges.
func (a *Analyzer) Analyze(
	_ context.Context,
	agents []types.CanonicalAgentRecord,
	refs []types.StaticRef,
	existingEdges []types.AgentEdgeRecord,
) ([]types.AgentEdgeRecord, []types.FindingRecord) {
	now := time.Now().UTC()

	// Build lookup indexes
	byExternalID := map[string]*types.CanonicalAgentRecord{}
	byPublicURL := map[string]*types.CanonicalAgentRecord{}
	for i := range agents {
		ag := &agents[i]
		if ag.ExternalID != "" {
			byExternalID[ag.ExternalID] = ag
		}
		if ag.PublicURL != "" {
			byPublicURL[normalizeURL(ag.PublicURL)] = ag
		}
		if ag.FunctionURL != "" {
			byPublicURL[normalizeURL(ag.FunctionURL)] = ag
		}
		if ag.APIGatewayURL != "" {
			byPublicURL[normalizeURL(ag.APIGatewayURL)] = ag
		}
	}

	// Build a set of existing edge pairs to avoid duplicates
	existingPairs := map[string]bool{}
	for _, e := range existingEdges {
		existingPairs[e.SourceStableID+"|"+e.TargetStableID+"|"+string(e.EdgeType)] = true
	}

	var newEdges []types.AgentEdgeRecord
	var findings []types.FindingRecord

	// Resolve each ref
	for _, ref := range refs {
		sourceAgent := byExternalID[ref.SourceAgentExternalID]
		if sourceAgent == nil {
			continue // source agent not in registry — skip
		}

		// Try to find target agent by externalId or URL
		targetAgent := resolveTarget(ref.TargetExternalID, byExternalID, byPublicURL)

		if targetAgent != nil {
			// Resolved — create an edge if not already present
			pairKey := sourceAgent.StableID + "|" + targetAgent.StableID + "|" + string(ref.EdgeType)
			if !existingPairs[pairKey] {
				existingPairs[pairKey] = true
				newEdges = append(newEdges, types.AgentEdgeRecord{
					SourceStableID: sourceAgent.StableID,
					TargetStableID: targetAgent.StableID,
					EdgeType:       ref.EdgeType,
					Confidence:     ref.Confidence,
					DiscoveredAt:   now,
					Evidence:       ref.Evidence,
				})
			}
		} else if ref.Confidence >= 0.65 {
			// Unresolved with sufficient confidence → AGENT_UNRESOLVED_DEPENDENCY
			evidence, _ := json.Marshal(map[string]string{
				"sourceAgent":      ref.SourceAgentExternalID,
				"targetExternalId": ref.TargetExternalID,
				"refSource":        ref.RefSource,
				"evidence":         ref.Evidence,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "AGENT_UNRESOLVED_DEPENDENCY",
				Severity:      "MEDIUM",
				AgentStableID: sourceAgent.StableID,
				AgentName:     sourceAgent.Name,
				Title:         "Agent references an unregistered dependency",
				Description: fmt.Sprintf(
					"Agent %s has a static reference to %q (via %s) that does not match any registered agent.",
					sourceAgent.Name, ref.TargetExternalID, ref.RefSource,
				),
				EvidenceJSON: evidence,
				DiscoveredAt: now,
				Plugin:       "staticref",
			})
		}
	}

	// Intent-based findings: MISSING_INTENT_DECLARATION, INTENT_MISMATCH, INTENT_OWNER_ABSENT
	for i := range agents {
		ag := &agents[i]
		intentFindings := intentFindings(ag, now)
		findings = append(findings, intentFindings...)
	}

	return newEdges, findings
}

// resolveTarget tries to match a target identifier against the known agent set.
// It checks: exact externalId match, prefix match for ARN-style resources,
// and URL match for HTTP endpoints.
func resolveTarget(
	targetID string,
	byExternalID map[string]*types.CanonicalAgentRecord,
	byPublicURL map[string]*types.CanonicalAgentRecord,
) *types.CanonicalAgentRecord {
	// Exact match
	if ag, ok := byExternalID[targetID]; ok {
		return ag
	}

	// URL match (normalize trailing slashes etc.)
	norm := normalizeURL(targetID)
	if ag, ok := byPublicURL[norm]; ok {
		return ag
	}

	// Prefix/suffix match — e.g. execute-api ARN matches a known API GW URL
	for extID, ag := range byExternalID {
		if strings.HasPrefix(extID, targetID) || strings.HasPrefix(targetID, extID) {
			return ag
		}
	}
	for urlKey, ag := range byPublicURL {
		if strings.Contains(norm, urlKey) || strings.Contains(urlKey, norm) {
			return ag
		}
	}

	return nil
}

// normalizeURL strips trailing slashes and lowercases the URL for comparison.
func normalizeURL(u string) string {
	return strings.ToLower(strings.TrimRight(u, "/"))
}

// intentFindings generates findings related to intent declarations for a single agent.
func intentFindings(ag *types.CanonicalAgentRecord, now time.Time) []types.FindingRecord {
	var findings []types.FindingRecord

	// Only apply to agents that look like AI agents
	if !isAIAgent(ag) {
		return nil
	}

	// MISSING_INTENT_DECLARATION: no intent file, or README with fewer than 50 words
	if ag.IntentStatement == "" {
		evidence, _ := json.Marshal(map[string]string{
			"agentName":     ag.Name,
			"platform":      ag.Platform,
			"visibilityClass": string(ag.VisibilityClass),
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MISSING_INTENT_DECLARATION",
			Severity:      "MEDIUM",
			AgentStableID: ag.StableID,
			AgentName:     ag.Name,
			Title:         "No intent declaration found for agent",
			Description: fmt.Sprintf(
				"Agent %s has no readable intent file (.specter/manifest.yaml, AGENT.md, CLAUDE.md) "+
					"and no README with sufficient description (≥50 words).",
				ag.Name,
			),
			EvidenceJSON: evidence,
			DiscoveredAt: now,
			Plugin:       "staticref",
		})
		return findings
	}

	// INTENT_MISMATCH: alignment score below threshold
	if ag.AlignmentScore > 0 && ag.AlignmentScore < 0.60 {
		evidence, _ := json.Marshal(map[string]interface{}{
			"agentName":      ag.Name,
			"alignmentScore": ag.AlignmentScore,
			"alignmentTier":  ag.AlignmentTier,
			"mismatches":     ag.AlignmentMismatch,
			"intentSource":   ag.IntentSource,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "INTENT_MISMATCH",
			Severity:      "HIGH",
			AgentStableID: ag.StableID,
			AgentName:     ag.Name,
			Title:         "Agent behaviour does not match stated intent",
			Description: fmt.Sprintf(
				"Agent %s has an alignment score of %.2f (%s). "+
					"Observed behaviour contradicts the intent declared in %s.",
				ag.Name, ag.AlignmentScore, ag.AlignmentTier, ag.IntentSource,
			),
			EvidenceJSON: evidence,
			DiscoveredAt: now,
			Plugin:       "staticref",
		})
	}

	// INTENT_OWNER_ABSENT: has intent file but no owner declared
	if ag.IntentStatement != "" && ag.IntentOwner == "" {
		evidence, _ := json.Marshal(map[string]string{
			"agentName":    ag.Name,
			"intentSource": ag.IntentSource,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "INTENT_OWNER_ABSENT",
			Severity:      "LOW",
			AgentStableID: ag.StableID,
			AgentName:     ag.Name,
			Title:         "Intent file present but no owner declared",
			Description: fmt.Sprintf(
				"Agent %s has an intent declaration in %s but no Owner/Maintainer field is set.",
				ag.Name, ag.IntentSource,
			),
			EvidenceJSON: evidence,
			DiscoveredAt: now,
			Plugin:       "staticref",
		})
	}

	return findings
}

// isAIAgent returns true if there is enough evidence this agent is an AI agent
// (has a detected framework, MCP/A2A protocol data, or was flagged by a plugin).
func isAIAgent(ag *types.CanonicalAgentRecord) bool {
	if ag.Framework != "" {
		return true
	}
	if ag.FunctionalClass != "" {
		return true
	}
	if ag.A2ACard != nil || ag.A2ACardURL != "" {
		return true
	}
	if ag.MCPManifest != nil {
		return true
	}
	if ag.Platform == "GITHUB" {
		return true // GitHub plugin only emits agents if they look like AI repos
	}
	return false
}
