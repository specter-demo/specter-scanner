// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"testing"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

func TestAccountRoleARN(t *testing.T) {
	got := accountRoleARN("111111111111", "SpecterReadOnly")
	want := "arn:aws:iam::111111111111:role/SpecterReadOnly"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// TestScanAccountsWithPartialFailure_ContinuesPastOneAccountFailure is the
// core regression test for partial-failure handling: one account's
// role-assumption failing (not onboarded, access denied) must not abort
// the whole multi-account scan — the remaining accounts must still be
// attempted and their results still merged in.
func TestScanAccountsWithPartialFailure_ContinuesPastOneAccountFailure(t *testing.T) {
	accountIDs := []string{"111111111111", "222222222222", "333333333333"}
	scanOne := func(accountID string) (*plugin.ScanResult, error) {
		if accountID == "222222222222" {
			return nil, errors.New("AccessDenied: role not onboarded in this account")
		}
		return &plugin.ScanResult{
			Agents: []types.CanonicalAgentRecord{{StableID: "agent-" + accountID, AccountID: accountID}},
		}, nil
	}

	combined, statuses := scanAccountsWithPartialFailure(accountIDs, scanOne)

	if len(statuses) != 3 {
		t.Fatalf("expected 3 account statuses (one per account attempted), got %d", len(statuses))
	}
	if len(combined.Agents) != 2 {
		t.Errorf("expected agents from the 2 successful accounts to be merged, got %d", len(combined.Agents))
	}

	byAccount := map[string]plugin.AccountScanResult{}
	for _, s := range statuses {
		byAccount[s.AccountID] = s
	}
	if byAccount["111111111111"].Status != "SUCCESS" {
		t.Errorf("expected 111111111111 to be SUCCESS, got %+v", byAccount["111111111111"])
	}
	if byAccount["222222222222"].Status != "FAILED" || byAccount["222222222222"].Error == "" {
		t.Errorf("expected 222222222222 to be FAILED with a non-empty error, got %+v", byAccount["222222222222"])
	}
	if byAccount["333333333333"].Status != "SUCCESS" {
		t.Errorf("expected 333333333333 (after the failed account) to still be attempted and SUCCESS, got %+v", byAccount["333333333333"])
	}
}

func TestScanAccountsWithPartialFailure_AllAccountsFail(t *testing.T) {
	accountIDs := []string{"111111111111", "222222222222"}
	scanOne := func(accountID string) (*plugin.ScanResult, error) {
		return nil, errors.New("AccessDenied")
	}

	combined, statuses := scanAccountsWithPartialFailure(accountIDs, scanOne)

	if len(statuses) != 2 {
		t.Fatalf("expected 2 account statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if s.Status != "FAILED" {
			t.Errorf("expected all accounts to report FAILED, got %+v", s)
		}
	}
	if len(combined.Agents) != 0 {
		t.Errorf("expected no agents when every account fails, got %d", len(combined.Agents))
	}
}

func TestScanAccountsWithPartialFailure_AllAccountsSucceed(t *testing.T) {
	accountIDs := []string{"111111111111", "222222222222"}
	scanOne := func(accountID string) (*plugin.ScanResult, error) {
		return &plugin.ScanResult{
			Agents: []types.CanonicalAgentRecord{{StableID: "agent-" + accountID, AccountID: accountID}},
		}, nil
	}

	combined, statuses := scanAccountsWithPartialFailure(accountIDs, scanOne)

	if len(statuses) != 2 {
		t.Fatalf("expected 2 account statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if s.Status != "SUCCESS" {
			t.Errorf("expected all accounts to report SUCCESS, got %+v", s)
		}
	}
	if len(combined.Agents) != 2 {
		t.Errorf("expected agents from both accounts merged, got %d", len(combined.Agents))
	}
}

func TestScanAccountsWithPartialFailure_NoAccounts(t *testing.T) {
	combined, statuses := scanAccountsWithPartialFailure(nil, func(accountID string) (*plugin.ScanResult, error) {
		t.Fatal("scanOne should never be called with an empty account list")
		return nil, nil
	})
	if len(statuses) != 0 {
		t.Errorf("expected no statuses for an empty account list, got %d", len(statuses))
	}
	if len(combined.Agents) != 0 {
		t.Errorf("expected no agents for an empty account list, got %d", len(combined.Agents))
	}
}

// TestScanAccountsWithPartialFailure_MergesConfirmedHumanPrincipals confirms
// the merge covers every ScanResult field a per-account Scan() can
// populate, not just Agents — including the map field, which needs an
// explicit merge (not a simple append) unlike the slice fields.
func TestScanAccountsWithPartialFailure_MergesConfirmedHumanPrincipals(t *testing.T) {
	accountIDs := []string{"111111111111", "222222222222"}
	scanOne := func(accountID string) (*plugin.ScanResult, error) {
		return &plugin.ScanResult{
			ConfirmedHumanPrincipals: map[string]bool{"principal-" + accountID: true},
		}, nil
	}

	combined, _ := scanAccountsWithPartialFailure(accountIDs, scanOne)

	if len(combined.ConfirmedHumanPrincipals) != 2 {
		t.Fatalf("expected ConfirmedHumanPrincipals merged from both accounts, got %+v", combined.ConfirmedHumanPrincipals)
	}
	if !combined.ConfirmedHumanPrincipals["principal-111111111111"] || !combined.ConfirmedHumanPrincipals["principal-222222222222"] {
		t.Errorf("expected both accounts' confirmed principals present, got %+v", combined.ConfirmedHumanPrincipals)
	}
}
