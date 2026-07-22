// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"testing"

	gogithub "github.com/google/go-github/v66/github"

	"github.com/specter-demo/specter-scanner/internal/types"
)

func repo(name string) *gogithub.Repository {
	return &gogithub.Repository{Name: &name}
}

func TestCorrelateOIDCDeployEdges_Match(t *testing.T) {
	repos := []*gogithub.Repository{repo("example-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{
			StableID:          "target-agent-stable-id",
			OIDCTrustSubjects: []string{"repo:example-org/example-repo:*"},
		},
	}

	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}
	edge := edges[0]
	if edge.TargetStableID != "target-agent-stable-id" {
		t.Errorf("expected TargetStableID %q, got %q", "target-agent-stable-id", edge.TargetStableID)
	}
	if edge.EdgeType != types.EdgeTypeOIDCDeploy {
		t.Errorf("expected EdgeType OIDC_DEPLOY, got %q", edge.EdgeType)
	}
	if edge.SourceStableID == "" {
		t.Error("expected a non-empty SourceStableID for the repo identity")
	}
	if edge.SourceStableID == edge.TargetStableID {
		t.Error("expected the repo-derived stableID and the agent's own stableID to differ (different hash inputs)")
	}
}

func TestCorrelateOIDCDeployEdges_SourceStableIDDeterministic(t *testing.T) {
	// The repo-side stableID must be computed the same way regardless of
	// which agent it happens to correlate to, so the same repo referenced
	// by two different roles' trust policies produces edges from the same
	// source node rather than two disconnected ones.
	repos := []*gogithub.Repository{repo("example-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "agent-a", OIDCTrustSubjects: []string{"repo:example-org/example-repo:*"}},
		{StableID: "agent-b", OIDCTrustSubjects: []string{"repo:example-org/example-repo:ref:refs/heads/main"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}
	if edges[0].SourceStableID != edges[1].SourceStableID {
		t.Errorf("expected both edges to share the same repo-derived SourceStableID, got %q and %q", edges[0].SourceStableID, edges[1].SourceStableID)
	}
}

func TestCorrelateOIDCDeployEdges_RepoNotFoundInScan_NoEdge(t *testing.T) {
	// The trust policy references a repo this scan didn't actually find —
	// renamed, deleted, or simply a stale/decommissioned trust policy. Must
	// not fabricate an edge to a repo that doesn't exist in the org today.
	repos := []*gogithub.Repository{repo("unrelated-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "target-agent", OIDCTrustSubjects: []string{"repo:example-org/deleted-repo:*"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 0 {
		t.Errorf("expected no edges when the subject's repo isn't in the scanned repo list, got %+v", edges)
	}
}

func TestCorrelateOIDCDeployEdges_WrongOrg_NoEdge(t *testing.T) {
	// A trust policy subject scoped to a different GitHub org entirely
	// (e.g. a role shared across orgs, or copy-pasted from another setup)
	// must not correlate against this org's repos.
	repos := []*gogithub.Repository{repo("example-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "target-agent", OIDCTrustSubjects: []string{"repo:different-org/example-repo:*"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 0 {
		t.Errorf("expected no edges when the subject's org doesn't match the scanned org, got %+v", edges)
	}
}

func TestCorrelateOIDCDeployEdges_OrgComparisonCaseInsensitive(t *testing.T) {
	repos := []*gogithub.Repository{repo("Example-Repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "target-agent", OIDCTrustSubjects: []string{"repo:Example-Org/example-repo:*"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "Example-Org", repos, seedAgents)
	if len(edges) != 1 {
		t.Errorf("expected case-insensitive org/repo matching to still produce 1 edge, got %d", len(edges))
	}
}

func TestCorrelateOIDCDeployEdges_NoOIDCTrustSubjects_NoEdges(t *testing.T) {
	repos := []*gogithub.Repository{repo("example-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "ordinary-agent"}, // no OIDCTrustSubjects at all — the common case
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if edges != nil {
		t.Errorf("expected nil edges when no seed agent has any OIDC trust subjects, got %+v", edges)
	}
}

func TestCorrelateOIDCDeployEdges_MalformedSubject_Skipped(t *testing.T) {
	repos := []*gogithub.Repository{repo("example-repo")}
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "target-agent", OIDCTrustSubjects: []string{"not-a-repo-scoped-subject"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 0 {
		t.Errorf("expected malformed subjects to be skipped rather than produce a bad edge, got %+v", edges)
	}
}

func TestCorrelateOIDCDeployEdges_NoRepos_NoEdges(t *testing.T) {
	seedAgents := []types.CanonicalAgentRecord{
		{StableID: "target-agent", OIDCTrustSubjects: []string{"repo:example-org/example-repo:*"}},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", nil, seedAgents)
	if edges != nil {
		t.Errorf("expected nil when no repos were scanned, got %+v", edges)
	}
}

func TestCorrelateOIDCDeployEdges_NoSeedAgents_NoEdges(t *testing.T) {
	repos := []*gogithub.Repository{repo("example-repo")}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, nil)
	if edges != nil {
		t.Errorf("expected nil when there are no seed agents, got %+v", edges)
	}
}

// TestCorrelateOIDCDeployEdges_RepoNameDiffersFromAgentName is the case
// this correlation exists to catch beyond simple name-matching: a shared
// deploy-infra repo (or any repo not sharing the target Lambda/ECS agent's
// name) with OIDC trust to a specific agent's role.
func TestCorrelateOIDCDeployEdges_RepoNameDiffersFromAgentName(t *testing.T) {
	repos := []*gogithub.Repository{repo("shared-deploy-infra")}
	seedAgents := []types.CanonicalAgentRecord{
		{
			Name:              "CustomerInsight-Orchestrator",
			StableID:          "customer-insight-stable-id",
			OIDCTrustSubjects: []string{"repo:example-org/shared-deploy-infra:*"},
		},
	}
	edges := correlateOIDCDeployEdges("test-org", "example-org", repos, seedAgents)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge correlating the differently-named repo to its agent, got %d", len(edges))
	}
	if edges[0].TargetStableID != "customer-insight-stable-id" {
		t.Errorf("expected TargetStableID %q, got %q", "customer-insight-stable-id", edges[0].TargetStableID)
	}
}
