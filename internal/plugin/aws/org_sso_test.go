// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"testing"

	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
)

// ── ORG_CROSS_ACCOUNT_NO_EXTERNAL_ID ──────────────────────────────────────────

func TestParseCrossAccountTrustStatements_ExternalIdPresent(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/example-partner-role"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"example-external-id"}}}]}`
	stmts := parseCrossAccountTrustStatements(doc)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 parsed statement, got %d", len(stmts))
	}
	if !stmts[0].hasExternalID {
		t.Error("expected hasExternalID to be true when the trust policy has a sts:ExternalId condition")
	}
	if stmts[0].principalAccountID != "222222222222" {
		t.Errorf("expected principalAccountID 222222222222, got %q", stmts[0].principalAccountID)
	}
}

func TestParseCrossAccountTrustStatements_ExternalIdAbsent(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	stmts := parseCrossAccountTrustStatements(doc)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 parsed statement, got %d", len(stmts))
	}
	if stmts[0].hasExternalID {
		t.Error("expected hasExternalID to be false when the trust policy has no Condition block at all")
	}
}

func TestParseCrossAccountTrustStatements_MalformedJSON(t *testing.T) {
	stmts := parseCrossAccountTrustStatements(`not valid json {{{`)
	if stmts != nil {
		t.Errorf("expected nil for malformed trust policy JSON, got %+v", stmts)
	}
}

func TestParseCrossAccountTrustStatements_DenyEffectIgnored(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	stmts := parseCrossAccountTrustStatements(doc)
	if len(stmts) != 0 {
		t.Errorf("expected a Deny-effect statement to be ignored, got %+v", stmts)
	}
}

// TestIsSameOrUnknownAccount_SameAccount is a regression test for the
// same-account exclusion: an IAM role that trusts its own account to
// assume it isn't a cross-account grant at all, and must not fire
// ORG_CROSS_ACCOUNT_NO_EXTERNAL_ID.
func TestIsSameOrUnknownAccount_SameAccount(t *testing.T) {
	if !isSameOrUnknownAccount("222222222222", "222222222222") {
		t.Error("expected a principal account matching the scanned account itself to be excluded")
	}
}

func TestIsSameOrUnknownAccount_DifferentAccount(t *testing.T) {
	if isSameOrUnknownAccount("222222222222", "111111111111") {
		t.Error("expected a principal account different from the scanned account to NOT be excluded")
	}
}

func TestIsSameOrUnknownAccount_UnknownAccount(t *testing.T) {
	if !isSameOrUnknownAccount("", "111111111111") {
		t.Error("expected an unresolvable (empty) principal account ID to be excluded rather than flagged")
	}
}

// TestIsAWSManagedOrgAccessRole is a regression test for the
// OrganizationAccountAccessRole exclusion: this is AWS's own default
// cross-account role, created automatically in every member account, with
// no sts:ExternalId condition by AWS's own design — it must never be
// flagged as a customer misconfiguration.
func TestIsAWSManagedOrgAccessRole_Excluded(t *testing.T) {
	if !isAWSManagedOrgAccessRole("OrganizationAccountAccessRole") {
		t.Error("expected the AWS-managed OrganizationAccountAccessRole to be excluded from the ExternalId check")
	}
}

func TestIsAWSManagedOrgAccessRole_CustomerRoleNotExcluded(t *testing.T) {
	if isAWSManagedOrgAccessRole("example-cross-account-deploy-role") {
		t.Error("expected an ordinary customer-created role name to NOT be treated as the AWS-managed exclusion")
	}
}

// ── ORPHANED_PERMISSION_SET ───────────────────────────────────────────────────

func TestIsAssigned_ZeroAssignments(t *testing.T) {
	if isAssigned(nil) {
		t.Error("expected zero assignments to report as not assigned")
	}
	if isAssigned([]ssoadmintypes.AccountAssignment{}) {
		t.Error("expected an empty (non-nil) assignments slice to report as not assigned")
	}
}

func TestIsAssigned_HasAssignments(t *testing.T) {
	assignments := []ssoadmintypes.AccountAssignment{
		{AccountId: strPtr("333333333333"), PrincipalId: strPtr("example-principal-id")},
	}
	if !isAssigned(assignments) {
		t.Error("expected a non-empty assignments slice to report as assigned")
	}
}

func strPtr(s string) *string { return &s }

// ── resolveHumanPrincipals / ssoPermissionSetNameFromARN ──────────────────────

func TestSsoPermissionSetNameFromARN_ValidSSOArn(t *testing.T) {
	arn := "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123def456/jane.doe"
	name, ok := ssoPermissionSetNameFromARN(arn)
	if !ok {
		t.Fatal("expected ok=true for a valid AWSReservedSSO_ ARN")
	}
	if name != "AdministratorAccess" {
		t.Errorf("expected permission set name %q, got %q", "AdministratorAccess", name)
	}
}

func TestSsoPermissionSetNameFromARN_MultiWordPermissionSetName(t *testing.T) {
	arn := "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ReadOnlyAccess_789xyz012/john.smith"
	name, ok := ssoPermissionSetNameFromARN(arn)
	if !ok {
		t.Fatal("expected ok=true for a valid AWSReservedSSO_ ARN")
	}
	if name != "ReadOnlyAccess" {
		t.Errorf("expected permission set name %q, got %q", "ReadOnlyAccess", name)
	}
}

func TestSsoPermissionSetNameFromARN_NonSSORole(t *testing.T) {
	arn := "arn:aws:sts::111111111111:assumed-role/example-agent-execution-role/example-session-id"
	_, ok := ssoPermissionSetNameFromARN(arn)
	if ok {
		t.Error("expected ok=false for a non-SSO agent role ARN")
	}
}

func TestSsoPermissionSetNameFromARN_EmptyString(t *testing.T) {
	_, ok := ssoPermissionSetNameFromARN("")
	if ok {
		t.Error("expected ok=false for an empty string")
	}
}

func TestSsoPermissionSetNameFromARN_MalformedNoUnderscore(t *testing.T) {
	// AWSReservedSSO_ prefix present, but nothing shaped like
	// "<name>_<hash>" after it — no underscore to split on at all.
	arn := "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_/jane.doe"
	_, ok := ssoPermissionSetNameFromARN(arn)
	if ok {
		t.Error("expected ok=false when there's no _<hash> suffix to split off")
	}
}
