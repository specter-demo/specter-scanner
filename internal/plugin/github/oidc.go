// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	"github.com/specter-demo/specter-scanner/internal/plugin/shared"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// oidcDeployEdgeConfidence matches the confidence used for other directly-
// resolved (not fuzzy-matched) edges the AWS plugin emits — see
// discoverExternalAgents's EdgeTypeEnvURL edges in internal/plugin/aws/aws.go.
// A parsed IAM trust-policy condition is a structurally verified fact, not
// an inference, so this is at the high end rather than a StaticRef-style
// heuristic confidence.
const oidcDeployEdgeConfidence = 0.85

// correlateOIDCDeployEdges matches every AWS-parsed OIDC trust subject
// (agent.OIDCTrustSubjects, populated by the AWS plugin's enrichIAMRole —
// see internal/plugin/aws/oidc.go) against the repos this GitHub scan
// actually found, and emits an EdgeTypeOIDCDeploy edge for each match —
// specter-scanner-spec.docx §5.2 step 6.
//
// Deliberately independent of matchSeedAgent's name-based correlation used
// elsewhere in this file: a deploying repo has no reason to share a name
// with the agent its OIDC role deploys to (a shared "infra-deploy" repo
// deploying several differently-named Lambda functions is a normal,
// real-world shape), so this checks every seed agent against every repo
// rather than only the repo scanRepo already matched by name.
//
// The edge's source is a deterministic stableID computed from the repo's
// own identity ("github:{org}/{repo}"), the same formula
// buildGitHubNativeAgentRecord uses for Tier 2 agent records — not
// necessarily an agent record that exists in this scan's results. This
// mirrors the AWS plugin's own discoverExternalAgents, which routes
// EdgeTypeEnvURL edges to a deterministic external-identity stableID
// whether or not a matching agent record exists yet: an edge to a
// not-yet-resolved identity is an established, accepted shape in this
// codebase (see AGENT_UNRESOLVED_DEPENDENCY), not a bug to work around by
// force-creating an agent record for every deploy-infra repo regardless of
// whether it's actually agent-shaped.
func correlateOIDCDeployEdges(orgID, githubOrg string, repos []*gogithub.Repository, seedAgents []types.CanonicalAgentRecord) []types.AgentEdgeRecord {
	if githubOrg == "" || len(repos) == 0 || len(seedAgents) == 0 {
		return nil
	}

	repoNames := make(map[string]string, len(repos)) // lowercase name -> real name
	for _, r := range repos {
		name := r.GetName()
		repoNames[strings.ToLower(name)] = name
	}

	now := time.Now().UTC()
	var edges []types.AgentEdgeRecord

	for _, agent := range seedAgents {
		for _, subject := range agent.OIDCTrustSubjects {
			org, repo, ok := shared.ParseGitHubOIDCSubject(subject)
			if !ok {
				continue
			}
			if !strings.EqualFold(org, githubOrg) {
				continue
			}
			realRepoName, found := repoNames[strings.ToLower(repo)]
			if !found {
				continue // trust policy references a repo this scan didn't find (renamed, deleted, wrong org)
			}

			repoExternalID := "github:" + githubOrg + "/" + realRepoName
			edges = append(edges, types.AgentEdgeRecord{
				SourceStableID: stableID(orgID, repoExternalID),
				TargetStableID: agent.StableID,
				EdgeType:       types.EdgeTypeOIDCDeploy,
				Confidence:     oidcDeployEdgeConfidence,
				DiscoveredAt:   now,
				Evidence:       "IAM role trust policy grants sts:AssumeRoleWithWebIdentity for OIDC subject " + subject,
			})
		}
	}

	return edges
}
