// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import "testing"

// ── parseGitHubOIDCTrustSubjects ─────────────────────────────────────────────

func TestParseGitHubOIDCTrustSubjects_WildcardSubject(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
				"StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:*"}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if len(subjects) != 1 || subjects[0] != "repo:example-org/example-repo:*" {
		t.Fatalf("expected 1 subject %q, got %+v", "repo:example-org/example-repo:*", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_ExactRefViaStringEquals(t *testing.T) {
	// A trust policy pinning one exact branch uses StringEquals for the
	// subject condition instead of StringLike — must still be found; the
	// parser checks every condition block, not one hardcoded operator.
	doc := `{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if len(subjects) != 1 || subjects[0] != "repo:example-org/example-repo:ref:refs/heads/main" {
		t.Fatalf("expected 1 subject via StringEquals, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_MultipleSubjectsInOneCondition(t *testing.T) {
	// A role trusted by more than one repo has the subject condition as a
	// JSON array rather than a single string.
	doc := `{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringLike": {"token.actions.githubusercontent.com:sub": [
					"repo:example-org/repo-a:*",
					"repo:example-org/repo-b:*"
				]}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if len(subjects) != 2 {
		t.Fatalf("expected 2 subjects, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_OrdinaryECSTaskTrustPolicy_NoSubjects(t *testing.T) {
	// The overwhelmingly common case: a role trusted by ecs-tasks.amazonaws.com,
	// not any external OIDC provider. Must return nil, not an error.
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "ecs-tasks.amazonaws.com"},
			"Action": "sts:AssumeRole"
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if subjects != nil {
		t.Errorf("expected nil for an ordinary ECS task trust policy, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_DifferentOIDCProvider_Ignored(t *testing.T) {
	// A role federated to some other OIDC IdP (GitLab, Auth0, a different
	// CI system) in the same account must not be mistaken for GitHub's.
	doc := `{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/gitlab.example.com"},
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringLike": {"gitlab.example.com:sub": "project_path:example-org/example-repo:ref_type:branch:ref:main"}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if subjects != nil {
		t.Errorf("expected nil for a non-GitHub OIDC provider, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_DenyEffectIgnored(t *testing.T) {
	doc := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Condition": {
				"StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:*"}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if subjects != nil {
		t.Errorf("expected a Deny-effect statement to be ignored, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_WrongAction_Ignored(t *testing.T) {
	// Same Federated principal, but a different action — not actually an
	// OIDC web-identity assumption grant.
	doc := `{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:*"}
			}
		}]
	}`
	subjects := parseGitHubOIDCTrustSubjects(doc)
	if subjects != nil {
		t.Errorf("expected nil when the action isn't sts:AssumeRoleWithWebIdentity, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_MalformedJSON(t *testing.T) {
	subjects := parseGitHubOIDCTrustSubjects(`not valid json {{{`)
	if subjects != nil {
		t.Errorf("expected nil for malformed trust policy JSON, got %+v", subjects)
	}
}

func TestParseGitHubOIDCTrustSubjects_EmptyDocument(t *testing.T) {
	subjects := parseGitHubOIDCTrustSubjects("")
	if subjects != nil {
		t.Errorf("expected nil for an empty document, got %+v", subjects)
	}
}

// ── stringOrSliceValues ───────────────────────────────────────────────────────

func TestStringOrSliceValues_BareString(t *testing.T) {
	got := stringOrSliceValues("sts:AssumeRoleWithWebIdentity")
	if len(got) != 1 || got[0] != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("expected 1 value, got %+v", got)
	}
}

func TestStringOrSliceValues_Array(t *testing.T) {
	got := stringOrSliceValues([]interface{}{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("expected [a b], got %+v", got)
	}
}

func TestStringOrSliceValues_NonStringElementsSkipped(t *testing.T) {
	got := stringOrSliceValues([]interface{}{"a", 42, "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("expected non-string array elements to be skipped, got %+v", got)
	}
}

func TestStringOrSliceValues_NilOrOtherType(t *testing.T) {
	if got := stringOrSliceValues(nil); got != nil {
		t.Errorf("expected nil for nil input, got %+v", got)
	}
	if got := stringOrSliceValues(42); got != nil {
		t.Errorf("expected nil for a non-string, non-slice type, got %+v", got)
	}
}
