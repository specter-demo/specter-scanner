// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"testing"

	"github.com/specter-demo/specter-scanner/internal/types"
)

const (
	exampleRootRoleARN   = "arn:aws:iam::111111111111:role/example-root-agent-role"
	exampleTargetRoleARN = "arn:aws:iam::111111111111:role/example-target-agent-role"
	exampleOtherRoleARN  = "arn:aws:iam::111111111111:role/example-unrelated-agent-role"
)

// rootAndTarget builds the minimal two-agent, one-edge fixture Reconstruct
// needs to produce exactly one chain: a root agent (no inbound edges, one
// outbound edge) and a target agent it delegates to. Both carry an
// IAMRoleARN so hasHumanPrincipal has something to correlate events against.
func rootAndTarget(rootUnattendedConfirmed bool) ([]types.CanonicalAgentRecord, []types.AgentEdgeRecord) {
	agents := []types.CanonicalAgentRecord{
		{StableID: "root-agent", Name: "example-root", IAMRoleARN: exampleRootRoleARN, UnattendedTriggerConfirmed: rootUnattendedConfirmed},
		{StableID: "target-agent", Name: "example-target", IAMRoleARN: exampleTargetRoleARN},
	}
	edges := []types.AgentEdgeRecord{
		{SourceStableID: "root-agent", TargetStableID: "target-agent", EdgeType: types.EdgeTypeSTSAssume},
	}
	return agents, edges
}

// ── UnattendedTriggerConfirmed primary signal (Part A, unchanged) ────────────

func TestReconstruct_UnattendedTriggerConfirmed_PrimarySignal(t *testing.T) {
	agents, edges := rootAndTarget(true)
	// No events at all — if the primary signal weren't wired in ahead of
	// hasHumanPrincipal, this chain would have no way to end up unattended.
	var events []types.NormalizedEvent

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true from UnattendedTriggerConfirmed alone, with no events present")
	}
}

func TestReconstruct_UnattendedTriggerConfirmed_ShortCircuitsHasHumanPrincipal(t *testing.T) {
	// Even when a real human event is present for the root, the
	// authoritative EventBridge signal must still win — it's a positive
	// confirmation, not just "no evidence found either way".
	agents, edges := rootAndTarget(true)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane.doe"}, AssumedRoleARN: exampleRootRoleARN},
	}

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected UnattendedTriggerConfirmed to still win over a HUMAN event present for the root")
	}
}

// ── hasHumanPrincipal fallback (Step 2) ───────────────────────────────────────

func TestReconstruct_HasHumanPrincipal_HumanFoundOnRoot_NotUnattended(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane.doe"}, AssumedRoleARN: exampleRootRoleARN},
	}

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].IsUnattended {
		t.Error("expected IsUnattended=false: a HUMAN principal assumed the root agent's own IAM role")
	}
}

func TestReconstruct_HasHumanPrincipal_HumanFoundOnHop_NotUnattended(t *testing.T) {
	// Chain-scoped means root OR any hop — a human showing up partway
	// through the chain still counts.
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane.doe"}, AssumedRoleARN: exampleTargetRoleARN},
	}

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].IsUnattended {
		t.Error("expected IsUnattended=false: a HUMAN principal assumed a hop agent's IAM role")
	}
}

// TestReconstruct_HasHumanPrincipal_NoHumanFound_Unattended is the
// fallback-path regression test: with UnattendedTriggerConfirmed=false and
// no HUMAN principal found anywhere in the chain, IsUnattended must be
// true — per spec §7.1's own definition (IsUnattended = !hasHumanPrincipal),
// absence of evidence of human involvement is treated as unattended, not
// as unknown. This is a deliberate behavior change from the old
// global-SCHEDULER-scan fallback, which defaulted to false when it found
// no SCHEDULER event.
func TestReconstruct_HasHumanPrincipal_NoHumanFound_Unattended(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "AGENT", ID: "arn:aws:sts::111111111111:assumed-role/example-other-agent-role/session"}, AssumedRoleARN: exampleRootRoleARN},
	}

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true when no HUMAN principal is found anywhere in the chain")
	}
}

func TestReconstruct_HasHumanPrincipal_NoEventsAtAll_Unattended(t *testing.T) {
	agents, edges := rootAndTarget(false)
	var events []types.NormalizedEvent

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true when there are no events to correlate at all")
	}
}

// TestReconstruct_HasHumanPrincipal_IsChainScoped is the chain-scoping
// regression test: a HUMAN event correlated to an agent's role ARN that is
// NOT part of this chain must not count — the old check scanned every
// event in the entire scan regardless of which chain it belonged to.
func TestReconstruct_HasHumanPrincipal_IsChainScoped(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane.doe"}, AssumedRoleARN: exampleOtherRoleARN},
	}

	chains := Reconstruct(agents, edges, events, nil)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if !chains[0].IsUnattended {
		t.Error("expected IsUnattended=true: the HUMAN event belongs to an agent outside this chain and must not be counted")
	}
}

// ── Identity Center override (Step 3) ─────────────────────────────────────────

func TestReconstruct_ConfirmedHumanPrincipals_OverridesMisclassifiedType(t *testing.T) {
	// The event's own Principal.Type says AGENT (as if extractPrincipal
	// had misclassified it, or simply hadn't resolved it), but Identity
	// Center authoritatively confirms this exact principal is human — that
	// must win.
	agents, edges := rootAndTarget(false)
	principalARN := "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane.doe"
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "AGENT", ID: principalARN}, AssumedRoleARN: exampleRootRoleARN},
	}
	confirmedHumanPrincipals := map[string]bool{principalARN: true}

	chains := Reconstruct(agents, edges, events, confirmedHumanPrincipals)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].IsUnattended {
		t.Error("expected IsUnattended=false: Identity Center authoritatively confirmed this principal is human, overriding Principal.Type")
	}
}

// TestReconstruct_ConfirmedHumanPrincipals_UnresolvedFallsBackToCloudTrail is
// the fallback-to-hasHumanPrincipal regression test for Step 3
// specifically: when the confirmedHumanPrincipals map doesn't have an
// entry for this principal at all (Identity Center couldn't resolve it —
// e.g. a non-SSO IAM user, or a cross-account principal outside this Org),
// the CloudTrail-inferred Principal.Type must still be consulted, not
// silently treated as "not human".
func TestReconstruct_ConfirmedHumanPrincipals_UnresolvedFallsBackToCloudTrail(t *testing.T) {
	agents, edges := rootAndTarget(false)
	events := []types.NormalizedEvent{
		{Principal: types.Principal{Type: "HUMAN", ID: "arn:aws:iam::111111111111:user/example-non-sso-user"}, AssumedRoleARN: exampleRootRoleARN},
	}
	// A non-empty map that simply has no entry for this event's principal —
	// distinct from nil, to prove "absent from the map" (not "map is nil")
	// is what triggers the fallback.
	confirmedHumanPrincipals := map[string]bool{"arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/someone-else": true}

	chains := Reconstruct(agents, edges, events, confirmedHumanPrincipals)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].IsUnattended {
		t.Error("expected IsUnattended=false: Identity Center didn't resolve this principal, so Principal.Type==HUMAN (CloudTrail inference) should still apply")
	}
}
