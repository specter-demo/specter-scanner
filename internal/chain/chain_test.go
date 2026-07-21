// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"testing"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// rootAndTarget builds the minimal two-agent, one-edge fixture Reconstruct
// needs to produce exactly one chain: a root agent (no inbound edges, one
// outbound edge) and a target agent it delegates to.
func rootAndTarget(rootUnattendedConfirmed bool) ([]types.CanonicalAgentRecord, []types.AgentEdgeRecord) {
	agents := []types.CanonicalAgentRecord{
		{StableID: "root-agent", Name: "example-root", UnattendedTriggerConfirmed: rootUnattendedConfirmed},
		{StableID: "target-agent", Name: "example-target"},
	}
	edges := []types.AgentEdgeRecord{
		{SourceStableID: "root-agent", TargetStableID: "target-agent", EdgeType: types.EdgeTypeSTSAssume},
	}
	return agents, edges
}

func TestReconstruct_UnattendedTriggerConfirmed_PrimarySignal(t *testing.T) {
	agents, edges := rootAndTarget(true)
	// No CloudTrail events at all — if the primary signal weren't wired
	// in, this chain would have no way to end up marked unattended.
	var events []types.NormalizedEvent

	chains := Reconstruct(agents, edges, events)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true from UnattendedTriggerConfirmed alone, with no CloudTrail events present")
	}
}

// TestReconstruct_FallsBackToCloudTrailInference is the fallback-path
// regression test: when direct enumeration found nothing for this agent
// (UnattendedTriggerConfirmed=false), CloudTrail-inferred SCHEDULER
// detection must still work exactly as it did before the primary signal
// was added — this must not have quietly regressed.
func TestReconstruct_FallsBackToCloudTrailInference(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "SCHEDULER", ID: "arn:aws:events:us-east-1:111111111111:rule/example-schedule"}},
	}

	chains := Reconstruct(agents, edges, events)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true from the CloudTrail SCHEDULER-principal fallback when direct enumeration found nothing")
	}
}

func TestReconstruct_NeitherSignalPresent_NotUnattended(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:iam::111111111111:user/example-user"}},
	}

	chains := Reconstruct(agents, edges, events)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].IsUnattended {
		t.Error("expected IsUnattended=false when neither direct enumeration nor CloudTrail inference found a scheduler/EventBridge trigger")
	}
}

func TestReconstruct_UnattendedTriggerConfirmed_IgnoresEmptySchedulerPrincipalID(t *testing.T) {
	// A SCHEDULER-typed event with no Principal.ID shouldn't fire the
	// fallback path (mirrors the pre-existing CloudTrail-inference guard);
	// the primary signal being true is what determines the outcome here.
	agents, edges := rootAndTarget(true)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "SCHEDULER", ID: ""}},
	}

	chains := Reconstruct(agents, edges, events)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true driven by UnattendedTriggerConfirmed regardless of the malformed SCHEDULER event")
	}
}
