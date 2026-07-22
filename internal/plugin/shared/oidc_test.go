// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package shared

import "testing"

func TestParseGitHubOIDCSubject_WildcardBranch(t *testing.T) {
	org, repo, ok := ParseGitHubOIDCSubject("repo:example-org/example-repo:*")
	if !ok {
		t.Fatal("expected ok=true for a wildcard-scoped subject")
	}
	if org != "example-org" || repo != "example-repo" {
		t.Errorf("expected org=%q repo=%q, got org=%q repo=%q", "example-org", "example-repo", org, repo)
	}
}

func TestParseGitHubOIDCSubject_RefScoped(t *testing.T) {
	org, repo, ok := ParseGitHubOIDCSubject("repo:example-org/example-repo:ref:refs/heads/main")
	if !ok {
		t.Fatal("expected ok=true for a ref-scoped subject")
	}
	if org != "example-org" || repo != "example-repo" {
		t.Errorf("expected org=%q repo=%q, got org=%q repo=%q", "example-org", "example-repo", org, repo)
	}
}

func TestParseGitHubOIDCSubject_EnvironmentScoped(t *testing.T) {
	org, repo, ok := ParseGitHubOIDCSubject("repo:example-org/example-repo:environment:production")
	if !ok {
		t.Fatal("expected ok=true for an environment-scoped subject")
	}
	if org != "example-org" || repo != "example-repo" {
		t.Errorf("expected org=%q repo=%q, got org=%q repo=%q", "example-org", "example-repo", org, repo)
	}
}

func TestParseGitHubOIDCSubject_PullRequestScoped(t *testing.T) {
	org, repo, ok := ParseGitHubOIDCSubject("repo:example-org/example-repo:pull_request")
	if !ok {
		t.Fatal("expected ok=true for a pull_request-scoped subject")
	}
	if org != "example-org" || repo != "example-repo" {
		t.Errorf("expected org=%q repo=%q, got org=%q repo=%q", "example-org", "example-repo", org, repo)
	}
}

func TestParseGitHubOIDCSubject_NotRepoPrefixed(t *testing.T) {
	// GitHub also issues org-scoped and enterprise-scoped subjects that
	// aren't repo-scoped at all — repo-to-agent correlation has nothing to
	// match those against.
	_, _, ok := ParseGitHubOIDCSubject("organization:example-org")
	if ok {
		t.Error("expected ok=false for a subject with no repo: prefix")
	}
}

func TestParseGitHubOIDCSubject_NoSlashSeparator(t *testing.T) {
	_, _, ok := ParseGitHubOIDCSubject("repo:malformed-no-slash")
	if ok {
		t.Error("expected ok=false when the org/repo segment has no / separator")
	}
}

func TestParseGitHubOIDCSubject_EmptyString(t *testing.T) {
	_, _, ok := ParseGitHubOIDCSubject("")
	if ok {
		t.Error("expected ok=false for an empty string")
	}
}

func TestParseGitHubOIDCSubject_EmptyOrgOrRepo(t *testing.T) {
	_, _, ok := ParseGitHubOIDCSubject("repo:/example-repo:*")
	if ok {
		t.Error("expected ok=false when the org segment is empty")
	}
	_, _, ok = ParseGitHubOIDCSubject("repo:example-org/:*")
	if ok {
		t.Error("expected ok=false when the repo segment is empty")
	}
}
