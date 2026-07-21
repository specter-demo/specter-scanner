// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// scanEventBridgeTriggers enumerates EventBridge rules in the scanned
// account/region and, for each rule, resolves its target(s) back to an
// already-discovered agent by direct ARN match. A rule whose target ARN
// matches a known agent's ExternalID authoritatively confirms that agent
// has an EventBridge-mediated invocation path — no human clicked anything
// to start it — which is a strictly more reliable signal than inferring
// the same fact from whether a SCHEDULER-attributed CloudTrail event
// happened to fall inside the scan's lookback window. See
// chain.Reconstruct, which uses UnattendedTriggerConfirmed as the primary
// signal and falls back to that CloudTrail inference only when this
// enumeration leaves it false.
//
// Both a cron/rate ScheduleExpression rule and an EventPattern rule count
// here: CloudTrail's own SCHEDULER classification (extractPrincipal, in
// aws.go) already conflates the two — any Lambda invocation whose
// eventSource is events.amazonaws.com is marked SCHEDULER regardless of
// which kind of rule triggered it. This enumeration mirrors that same
// scope rather than narrowing it, so it's a strict accuracy upgrade over
// the existing signal, not a redefinition of it.
//
// Scope is intentionally limited to the direct rule → target → agent hop
// (the "EventBridge → Lambda" single-hop case in spec §7.1): if a rule's
// target is an intermediate service (SNS, Step Functions, etc.) rather
// than the agent itself, no confirmation is recorded for it, since this
// scanner has no visibility into whether a human-approval step sits
// downstream of that intermediate hop.
func (p *Plugin) scanEventBridgeTriggers(ctx context.Context, agents []types.CanonicalAgentRecord) {
	client := eventbridge.NewFromConfig(p.awsConf)

	agentByExternalID := make(map[string]string, len(agents))
	agentsByStableID := make(map[string]*types.CanonicalAgentRecord, len(agents))
	for i := range agents {
		if agents[i].ExternalID != "" {
			agentByExternalID[agents[i].ExternalID] = agents[i].StableID
		}
		agentsByStableID[agents[i].StableID] = &agents[i]
	}

	var nextToken *string
	for {
		out, err := client.ListRules(ctx, &eventbridge.ListRulesInput{NextToken: nextToken})
		if err != nil {
			log.Printf("aws: EventBridge ListRules: %v", err)
			return
		}

		for _, rule := range out.Rules {
			confirmed := p.eventBridgeRuleConfirmedAgents(ctx, client, rule, agentByExternalID)
			for _, stableID := range confirmed {
				if agent, ok := agentsByStableID[stableID]; ok {
					agent.UnattendedTriggerConfirmed = true
				}
			}
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
}

// eventBridgeRuleConfirmedAgents lists one rule's targets (paginated) and
// returns the StableIDs of agents whose ExternalID directly matches a
// target ARN.
func (p *Plugin) eventBridgeRuleConfirmedAgents(ctx context.Context, client *eventbridge.Client, rule ebtypes.Rule, agentByExternalID map[string]string) []string {
	var confirmed []string
	var nextToken *string
	for {
		out, err := client.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			Rule:      rule.Name,
			NextToken: nextToken,
		})
		if err != nil {
			log.Printf("aws: EventBridge ListTargetsByRule(%s): %v", aws.ToString(rule.Name), err)
			return confirmed
		}

		confirmed = append(confirmed, matchEventBridgeTargetsToAgents(out.Targets, agentByExternalID)...)

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return confirmed
}

// matchEventBridgeTargetsToAgents checks each target's Arn against
// agentByExternalID (agent ExternalID → StableID) and returns the
// StableIDs of agents directly targeted by this rule.
func matchEventBridgeTargetsToAgents(targets []ebtypes.Target, agentByExternalID map[string]string) []string {
	var confirmed []string
	for _, target := range targets {
		if stableID, ok := agentByExternalID[aws.ToString(target.Arn)]; ok {
			confirmed = append(confirmed, stableID)
		}
	}
	return confirmed
}
