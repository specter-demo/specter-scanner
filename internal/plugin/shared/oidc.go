// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package shared

import "strings"

// ParseGitHubOIDCSubject splits a GitHub Actions OIDC subject claim into its
// org and repo components. Recognised shapes (all prefixed "repo:"):
// "repo:{org}/{repo}:*", "repo:{org}/{repo}:ref:refs/heads/{branch}",
// "repo:{org}/{repo}:environment:{name}", "repo:{org}/{repo}:pull_request".
//
// This is GitHub Actions OIDC subject-claim format, not a cloud-specific
// concept — a cloud plugin only needs to find the raw subject string in its
// own IAM/trust-policy shape (see internal/plugin/aws/oidc.go's
// parseGitHubOIDCTrustSubjects); parsing that string into org/repo is the
// same for every cloud, which is why it lives here rather than duplicated
// per cloud plugin.
//
// ok is false for anything that doesn't start with "repo:" or has no "/"
// separator in the org/repo segment — GitHub also issues org-scoped and
// enterprise-scoped OIDC tokens that aren't repo-scoped at all, which
// repo-to-agent correlation has nothing to match against.
func ParseGitHubOIDCSubject(subject string) (org, repo string, ok bool) {
	const prefix = "repo:"
	if !strings.HasPrefix(subject, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(subject, prefix)
	orgRepo := rest
	if colonIdx := strings.Index(rest, ":"); colonIdx >= 0 {
		orgRepo = rest[:colonIdx]
	}
	slashIdx := strings.Index(orgRepo, "/")
	if slashIdx < 0 {
		return "", "", false
	}
	org = orgRepo[:slashIdx]
	repo = orgRepo[slashIdx+1:]
	if org == "" || repo == "" {
		return "", "", false
	}
	return org, repo, true
}
