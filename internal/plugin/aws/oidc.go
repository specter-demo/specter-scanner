// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"encoding/json"
	"strings"
)

// githubOIDCSubjectConditionKey is the IAM condition key GitHub Actions'
// OIDC provider populates with the repo/ref-scoped subject claim. See
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
const githubOIDCSubjectConditionKey = "token.actions.githubusercontent.com:sub"

// githubOIDCFederatedPrincipalSuffix identifies a trust statement's
// Federated principal as GitHub's own OIDC provider specifically, as
// opposed to some other OIDC IdP (Auth0, GitLab, a different CI system)
// federated into the same AWS account.
const githubOIDCFederatedPrincipalSuffix = "oidc-provider/token.actions.githubusercontent.com"

// parseGitHubOIDCTrustSubjects parses an IAM role trust policy
// (AssumeRolePolicyDocument, already percent-decoded via
// decodeIAMPolicyDoc) for GitHub Actions OIDC federation statements and
// returns every subject claim found — e.g. "repo:example-org/example-
// repo:*" or "repo:example-org/example-repo:ref:refs/heads/main". Returns
// nil when the trust policy has no GitHub Actions OIDC statement at all,
// which is the overwhelmingly common case (most roles trust
// ecs-tasks.amazonaws.com or lambda.amazonaws.com, not an external OIDC
// provider) — not a parse error.
func parseGitHubOIDCTrustSubjects(doc string) []string {
	var policy struct {
		Statement []struct {
			Effect    string `json:"Effect"`
			Principal struct {
				Federated interface{} `json:"Federated"`
			} `json:"Principal"`
			Action    interface{}                       `json:"Action"`
			Condition map[string]map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil
	}

	var subjects []string
	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !containsFold(stringOrSliceValues(stmt.Action), "sts:AssumeRoleWithWebIdentity") {
			continue
		}
		if !hasSuffixAny(stringOrSliceValues(stmt.Principal.Federated), githubOIDCFederatedPrincipalSuffix) {
			continue
		}
		// The subject condition can appear under any condition operator —
		// StringLike for wildcard-scoped subjects ("repo:org/repo:*"),
		// StringEquals for a single exact ref. Check every condition block
		// present rather than assuming one specific operator.
		for _, condBlock := range stmt.Condition {
			raw, ok := condBlock[githubOIDCSubjectConditionKey]
			if !ok {
				continue
			}
			subjects = append(subjects, stringOrSliceValues(raw)...)
		}
	}
	return subjects
}

// stringOrSliceValues normalizes an IAM policy field that may be a bare
// string or a JSON array of strings — Action, Principal.Federated, and
// Condition operator values can each take either shape — into a flat
// string slice. Non-string array elements are skipped rather than erroring,
// matching parseIAMPolicy's existing tolerance for malformed entries.
func stringOrSliceValues(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func hasSuffixAny(values []string, suffix string) bool {
	for _, v := range values {
		if strings.HasSuffix(v, suffix) {
			return true
		}
	}
	return false
}
