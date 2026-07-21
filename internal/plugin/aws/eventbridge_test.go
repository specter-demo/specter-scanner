// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

func TestMatchEventBridgeTargetsToAgents_DirectMatch(t *testing.T) {
	targets := []ebtypes.Target{
		{Id: aws.String("t1"), Arn: aws.String("arn:aws:lambda:us-east-1:111111111111:function:example-nightly-job")},
	}
	agentByExternalID := map[string]string{
		"arn:aws:lambda:us-east-1:111111111111:function:example-nightly-job": "agent-stable-id-1",
	}

	got := matchEventBridgeTargetsToAgents(targets, agentByExternalID)
	if len(got) != 1 || got[0] != "agent-stable-id-1" {
		t.Errorf("expected a single match on agent-stable-id-1, got %+v", got)
	}
}

func TestMatchEventBridgeTargetsToAgents_NoMatch(t *testing.T) {
	targets := []ebtypes.Target{
		{Id: aws.String("t1"), Arn: aws.String("arn:aws:sns:us-east-1:111111111111:topic/unrelated-topic")},
	}
	agentByExternalID := map[string]string{
		"arn:aws:lambda:us-east-1:111111111111:function:example-nightly-job": "agent-stable-id-1",
	}

	got := matchEventBridgeTargetsToAgents(targets, agentByExternalID)
	if len(got) != 0 {
		t.Errorf("expected no matches for a target ARN not in agentByExternalID, got %+v", got)
	}
}

func TestMatchEventBridgeTargetsToAgents_IntermediateTargetNotConfirmed(t *testing.T) {
	// A rule targeting an SNS topic or Step Functions state machine, not
	// the agent directly — scope is intentionally limited to the direct
	// single-hop case, so this must not produce a confirmation even though
	// the agent is presumably invoked somewhere downstream of that hop.
	targets := []ebtypes.Target{
		{Id: aws.String("t1"), Arn: aws.String("arn:aws:states:us-east-1:111111111111:stateMachine:example-approval-workflow")},
	}
	agentByExternalID := map[string]string{
		"arn:aws:lambda:us-east-1:111111111111:function:example-nightly-job": "agent-stable-id-1",
	}

	got := matchEventBridgeTargetsToAgents(targets, agentByExternalID)
	if len(got) != 0 {
		t.Errorf("expected no confirmation for an intermediate (non-agent) target, got %+v", got)
	}
}

func TestMatchEventBridgeTargetsToAgents_MultipleTargetsSameRule(t *testing.T) {
	targets := []ebtypes.Target{
		{Id: aws.String("t1"), Arn: aws.String("arn:aws:lambda:us-east-1:111111111111:function:example-job-a")},
		{Id: aws.String("t2"), Arn: aws.String("arn:aws:lambda:us-east-1:111111111111:function:example-job-b")},
	}
	agentByExternalID := map[string]string{
		"arn:aws:lambda:us-east-1:111111111111:function:example-job-a": "agent-a",
		"arn:aws:lambda:us-east-1:111111111111:function:example-job-b": "agent-b",
	}

	got := matchEventBridgeTargetsToAgents(targets, agentByExternalID)
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(got), got)
	}
}

func TestMatchEventBridgeTargetsToAgents_EmptyTargets(t *testing.T) {
	got := matchEventBridgeTargetsToAgents(nil, map[string]string{"x": "y"})
	if len(got) != 0 {
		t.Errorf("expected no matches for an empty target list, got %+v", got)
	}
}
