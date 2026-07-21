// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"log"

	"github.com/specter-demo/specter-scanner/internal/plugin"
)

// Compile-time check that Plugin implements plugin.OrganizationScanner.
var _ plugin.OrganizationScanner = (*Plugin)(nil)

// defaultOrgReadOnlyRoleName is the read-only role name assumed in each
// member account when the caller doesn't specify one. Matches the
// already-established cross-account pattern (see infra/phase3/modules/
// specter_readonly in specter-platform): every member account deploys its
// own role literally named this, trusting the platform's own scanner
// identity — not a single Organizations-level role with automatic
// cross-account trust into every member.
const defaultOrgReadOnlyRoleName = "SpecterReadOnly"

// ScanOrganization implements plugin.OrganizationScanner: enumerates every
// active member account via Organizations.ListAccounts, then runs the
// existing, unmodified single-account Scan() once per account — assuming
// roleNameTemplate (a role name, not a full ARN; the account ID varies per
// iteration) in each one. Continues past an individual account's failure
// (role not deployed there yet, access denied, etc.) rather than aborting
// the whole run; every account attempted gets its own AccountScanResult,
// success or failure.
//
// This deliberately does not special-case the calling (management)
// account: every account ListAccounts returns is attempted uniformly,
// including the one the scanner is already running in. If that account
// has no SpecterReadOnly role of its own (there is no inherent reason it
// would — the platform's own identity doesn't need to assume a role into
// itself to see itself), it simply shows up as a FAILED entry like any
// other un-onboarded member account, which is the correct, honest
// per-account status.
func (p *Plugin) ScanOrganization(ctx context.Context, roleNameTemplate string) (*plugin.ScanResult, []plugin.AccountScanResult, error) {
	if roleNameTemplate == "" {
		roleNameTemplate = defaultOrgReadOnlyRoleName
	}

	// Establish the platform's own (pre-assumption) identity — needed to
	// call Organizations.ListAccounts, which is management-account-scoped
	// (same reasoning as Step 7's scanOrgAndSSO). Reuses loadAWSConfig's
	// standalone branch as a side effect: with RoleARN temporarily empty,
	// it just loads the default credential chain and sets p.baseAWSConf,
	// without assuming anything yet.
	origRoleARN := p.awsCfg.RoleARN
	origStandalone := p.awsCfg.StandaloneMode
	restore := func() {
		p.awsCfg.RoleARN = origRoleARN
		p.awsCfg.StandaloneMode = origStandalone
	}

	p.awsCfg.RoleARN = ""
	if _, err := p.loadAWSConfig(ctx); err != nil {
		restore()
		return nil, nil, fmt.Errorf("aws: load base identity for Organizations enumeration: %w", err)
	}

	accountIDs, err := p.listOrgAccountIDs(ctx)
	if err != nil {
		restore()
		return nil, nil, fmt.Errorf("aws: Organizations.ListAccounts: %w", err)
	}

	combined, statuses := scanAccountsWithPartialFailure(accountIDs, func(accountID string) (*plugin.ScanResult, error) {
		p.awsCfg.RoleARN = accountRoleARN(accountID, roleNameTemplate)
		p.awsCfg.StandaloneMode = false
		return p.Scan(ctx)
	})

	restore()
	return combined, statuses, nil
}

// accountRoleARN builds the per-account read-only role ARN for
// Organizations-based multi-account scanning.
func accountRoleARN(accountID, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
}

// scanAccountsWithPartialFailure calls scanOne once per account ID,
// continuing past an individual account's failure rather than aborting,
// and merges every successful account's ScanResult into one combined
// result. Extracted as a pure, injectable function (scanOne takes the
// place of the real per-account AWS calls) specifically so partial-failure
// behavior is unit-testable without live AWS credentials.
func scanAccountsWithPartialFailure(accountIDs []string, scanOne func(accountID string) (*plugin.ScanResult, error)) (*plugin.ScanResult, []plugin.AccountScanResult) {
	combined := &plugin.ScanResult{}
	statuses := make([]plugin.AccountScanResult, 0, len(accountIDs))

	for _, accountID := range accountIDs {
		result, err := scanOne(accountID)
		if err != nil {
			log.Printf("aws: account %s scan failed, continuing with remaining accounts: %v", accountID, err)
			statuses = append(statuses, plugin.AccountScanResult{
				AccountID: accountID,
				Status:    "FAILED",
				Error:     err.Error(),
			})
			continue
		}

		statuses = append(statuses, plugin.AccountScanResult{AccountID: accountID, Status: "SUCCESS"})
		if result == nil {
			continue
		}

		combined.Agents = append(combined.Agents, result.Agents...)
		combined.Edges = append(combined.Edges, result.Edges...)
		combined.Events = append(combined.Events, result.Events...)
		combined.Findings = append(combined.Findings, result.Findings...)
		combined.StaticRefs = append(combined.StaticRefs, result.StaticRefs...)
		if len(result.ConfirmedHumanPrincipals) > 0 {
			if combined.ConfirmedHumanPrincipals == nil {
				combined.ConfirmedHumanPrincipals = make(map[string]bool, len(result.ConfirmedHumanPrincipals))
			}
			for k, v := range result.ConfirmedHumanPrincipals {
				combined.ConfirmedHumanPrincipals[k] = v
			}
		}
	}

	return combined, statuses
}
