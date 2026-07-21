// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// awsManagedOrgAccessRoleName is the fixed role name AWS Organizations
// itself creates in every member account when the account is created
// (Organizations > "Access management for AWS accounts using AWS
// Organizations"). Its trust policy allows the management account to
// assume it with no sts:ExternalId condition, by AWS's own default design —
// it's not a customer misconfiguration, and flagging it would produce an
// identical, non-actionable finding in every AWS Organization that exists.
// Real scanners (Prowler, ScoutSuite) exclude this exact role name for the
// same reason; see its usage in scanCrossAccountTrustPolicies below.
const awsManagedOrgAccessRoleName = "OrganizationAccountAccessRole"

// isAWSManagedOrgAccessRole reports whether roleName is AWS Organizations'
// own default cross-account role — see awsManagedOrgAccessRoleName's doc
// comment for why it's excluded from the ExternalId check.
func isAWSManagedOrgAccessRole(roleName string) bool {
	return roleName == awsManagedOrgAccessRoleName
}

// scanOrgAndSSO implements Step 7: Organizations + IAM Identity Center
// (spec section 4.2). Organizations and Identity Center calls use
// p.baseAWSConf (the platform's own, pre-assumption identity) since both
// are management-account-scoped services the assumed SpecterReadOnly role
// in a member account cannot see.
//
// The cross-account trust-policy ExternalId check runs against p.awsConf
// (the account currently being scanned) instead, since it's inspecting IAM
// roles that live in that member account.
//
// Both sub-scans can surface findings on infrastructure that has no
// Lambda/ECS/Bedrock agent of its own (a bare cross-account IAM role, an
// Identity Center permission set) — knownAgents is used to correlate by
// name first, same as Step 6; when nothing correlates, a minimal agent
// record is synthesized and returned so the finding has a real,
// platform-valid AgentStableID to attach to (same precedent as
// discoverExternalAgents synthesizing EXTERNAL_HTTP records).
func (p *Plugin) scanOrgAndSSO(ctx context.Context, knownAgents []types.CanonicalAgentRecord) ([]types.CanonicalAgentRecord, []types.FindingRecord, error) {
	var newAgents []types.CanonicalAgentRecord
	var findings []types.FindingRecord

	orgAccountIDs, err := p.listOrgAccountIDs(ctx)
	if err != nil {
		// Not every account is the management account or a delegated admin —
		// this is expected to fail from most member accounts. Log and
		// continue: the ExternalId check below still runs, it just can't
		// scope "same Organization" as precisely without the account list.
		log.Printf("aws: organizations discovery unavailable (expected unless run from the management account): %v", err)
	}

	extAgents, extFindings := p.scanCrossAccountTrustPolicies(ctx, orgAccountIDs, knownAgents)
	newAgents = append(newAgents, extAgents...)
	findings = append(findings, extFindings...)

	ssoAgents, ssoFindings, err := p.scanOrphanedPermissionSets(ctx, orgAccountIDs, knownAgents)
	if err != nil {
		log.Printf("aws: identity center discovery unavailable (expected unless run from the management account): %v", err)
	} else {
		newAgents = append(newAgents, ssoAgents...)
		findings = append(findings, ssoFindings...)
	}

	return newAgents, findings, nil
}

// listOrgAccountIDs calls Organizations.ListAccounts using the base
// (pre-assumption) identity, returning every account ID in the org.
func (p *Plugin) listOrgAccountIDs(ctx context.Context) ([]string, error) {
	client := organizations.NewFromConfig(p.baseAWSConf)

	var ids []string
	var nextToken *string
	for {
		out, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ListAccounts: %w", err)
		}
		for _, acc := range out.Accounts {
			if acc.Status == orgtypes.AccountStatusActive {
				ids = append(ids, aws.ToString(acc.Id))
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return ids, nil
}

// scanCrossAccountTrustPolicies lists every IAM role in the currently
// scanned account and, for each whose trust policy allows sts:AssumeRole
// from another account in the same Organization, checks for an
// sts:ExternalId condition. This extends Step 4's IAM analysis rather than
// duplicating it — it uses the same GetRole/policy-decoding pattern as
// enrichIAMRole, just scoped to all roles instead of only roles already
// tied to a discovered agent (a cross-account target role like
// specter-demo-cross-account-sync-target-role has no Lambda/ECS/Bedrock
// agent of its own, so it would never be reached by enrichIAMRole's
// per-agent loop).
func (p *Plugin) scanCrossAccountTrustPolicies(ctx context.Context, orgAccountIDs []string, knownAgents []types.CanonicalAgentRecord) ([]types.CanonicalAgentRecord, []types.FindingRecord) {
	iamClient := iam.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var newAgents []types.CanonicalAgentRecord
	var findings []types.FindingRecord
	seenNewRoleARNs := map[string]bool{}

	selfAccountID := ""
	if out, err := sts.NewFromConfig(p.awsConf).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		selfAccountID = aws.ToString(out.Account)
	}

	orgAccounts := map[string]bool{}
	for _, id := range orgAccountIDs {
		orgAccounts[id] = true
	}

	var marker *string
	for {
		out, err := iamClient.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			log.Printf("aws: ListRoles: %v", err)
			return newAgents, findings
		}

		for _, role := range out.Roles {
			roleName := aws.ToString(role.RoleName)

			// See awsManagedOrgAccessRoleName's doc comment for why this
			// specific role is excluded — it's AWS's own default, not a
			// customer misconfiguration.
			if isAWSManagedOrgAccessRole(roleName) {
				continue
			}

			roleOut, err := iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
			if err != nil {
				continue
			}
			doc := decodeIAMPolicyDoc(aws.ToString(roleOut.Role.AssumeRolePolicyDocument))

			for _, stmt := range parseCrossAccountTrustStatements(doc) {
				if isSameOrUnknownAccount(stmt.principalAccountID, selfAccountID) {
					continue
				}
				// Scope to accounts confirmed in the same Organization when
				// we have that list; if Organizations wasn't reachable,
				// still flag it — a cross-account AssumeRole grant without
				// ExternalId is worth surfacing regardless.
				if len(orgAccounts) > 0 && !orgAccounts[stmt.principalAccountID] {
					continue
				}
				if stmt.hasExternalID {
					continue
				}

				roleArn := aws.ToString(roleOut.Role.Arn)

				// Attribute to a correlated agent if one exists; otherwise
				// synthesize a minimal record for the role itself, matching
				// discoverExternalAgents' precedent for infrastructure the
				// scanner discovers but that has no owning Lambda/ECS/Bedrock
				// resource (e.g. specter-demo-cross-account-sync-target-role
				// in partner-demo, which exists purely as a target role).
				agentStableID := ""
				agentName := roleName
				if matched := matchAgentByName(roleName, knownAgents); matched != nil {
					agentStableID = matched.StableID
					agentName = matched.Name
				} else {
					sid := stableID(p.cfg.OrgID, roleArn)
					agentStableID = sid
					if !seenNewRoleARNs[roleArn] {
						seenNewRoleARNs[roleArn] = true
						newAgents = append(newAgents, types.CanonicalAgentRecord{
							Name:             roleName,
							Platform:         "AWS_IAM_ROLE",
							ExternalID:       roleArn,
							StableID:         sid,
							OrgID:            p.cfg.OrgID,
							Region:           p.awsCfg.Region,
							LastSeenAt:       now,
							IAMRoleARN:       roleArn,
							VisibilitySource: "SCANNER",
						})
					}
				}

				evidence, _ := json.Marshal(map[string]string{
					"roleArn":          roleArn,
					"trustedPrincipal": stmt.principalARN,
					"trustedAccountId": stmt.principalAccountID,
				})
				findings = append(findings, types.FindingRecord{
					RuleID:        "ORG_CROSS_ACCOUNT_NO_EXTERNAL_ID",
					Severity:      "CRITICAL",
					AgentStableID: agentStableID,
					AgentName:     agentName,
					Title:         "Cross-account trust policy has no ExternalId condition",
					Description: fmt.Sprintf(
						"IAM role %s trusts %s to assume it, with no sts:ExternalId condition — any principal able to assume that role can assume this one too (confused-deputy risk).",
						roleName, stmt.principalARN,
					),
					EvidenceJSON: evidence,
					DiscoveredAt: now,
					Plugin:       "aws",
				})
			}
		}

		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	return newAgents, findings
}

// isSameOrUnknownAccount reports whether a trust statement's principal
// account should be excluded from the ExternalId check: either the
// principal's account ID couldn't be determined at all, or it's the same
// account currently being scanned — a same-account AssumeRole grant isn't
// cross-account and shouldn't be flagged by ORG_CROSS_ACCOUNT_NO_EXTERNAL_ID.
func isSameOrUnknownAccount(principalAccountID, selfAccountID string) bool {
	return principalAccountID == "" || principalAccountID == selfAccountID
}

// crossAccountTrustStatement is one parsed Statement entry from a trust
// (assume-role) policy document, reduced to the fields the ExternalId
// check needs.
type crossAccountTrustStatement struct {
	principalARN       string
	principalAccountID string
	hasExternalID      bool
}

// parseCrossAccountTrustStatements parses an assume-role trust policy
// document's Statement array, extracting the AWS principal (single string
// or list) and whether a sts:ExternalId condition is present. AWS
// account-root and account-generic principals (arn:aws:iam::<id>:root, or a
// bare 12-digit account ID) are both handled — CodeCommit/IAM commonly use
// either form.
func parseCrossAccountTrustStatements(doc string) []crossAccountTrustStatement {
	var policy struct {
		Statement []struct {
			Effect    string                            `json:"Effect"`
			Principal interface{}                       `json:"Principal"`
			Condition map[string]map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil
	}

	var result []crossAccountTrustStatement
	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		principals := extractAWSPrincipals(stmt.Principal)
		if len(principals) == 0 {
			continue
		}

		hasExternalID := false
		for _, condBlock := range stmt.Condition {
			if _, ok := condBlock["sts:ExternalId"]; ok {
				hasExternalID = true
			}
		}

		for _, principal := range principals {
			accountID := accountIDFromPrincipal(principal)
			result = append(result, crossAccountTrustStatement{
				principalARN:       principal,
				principalAccountID: accountID,
				hasExternalID:      hasExternalID,
			})
		}
	}
	return result
}

// extractAWSPrincipals normalizes a trust policy's Principal.AWS field,
// which can be a bare string, a nested {"AWS": "..."} map, or a
// {"AWS": [...]} map with a list, into a flat list of principal strings.
func extractAWSPrincipals(raw interface{}) []string {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	awsVal, ok := m["AWS"]
	if !ok {
		return nil
	}
	switch v := awsVal.(type) {
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
	}
	return nil
}

// accountIDFromPrincipal extracts the 12-digit account ID from an IAM
// principal ARN (arn:aws:iam::123456789012:role/... or :root) or a bare
// account ID string.
func accountIDFromPrincipal(principal string) string {
	if strings.HasPrefix(principal, "arn:aws:iam::") {
		parts := strings.Split(principal, ":")
		if len(parts) >= 5 {
			return parts[4]
		}
		return ""
	}
	if len(principal) == 12 && isAllDigits(principal) {
		return principal
	}
	return ""
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// scanOrphanedPermissionSets lists every IAM Identity Center permission set
// and, for each, checks whether it has zero account assignments across
// every account in the org — i.e. real access that was provisioned and
// then never actually granted to anyone.
func (p *Plugin) scanOrphanedPermissionSets(ctx context.Context, orgAccountIDs []string, knownAgents []types.CanonicalAgentRecord) ([]types.CanonicalAgentRecord, []types.FindingRecord, error) {
	client := ssoadmin.NewFromConfig(p.baseAWSConf)
	now := time.Now().UTC()
	var newAgents []types.CanonicalAgentRecord
	var findings []types.FindingRecord

	instanceArn, err := findSSOInstanceARN(ctx, client)
	if err != nil {
		return nil, nil, err
	}
	if instanceArn == "" {
		return nil, nil, fmt.Errorf("no IAM Identity Center instance found")
	}

	var nextToken *string
	for {
		listOut, err := client.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: aws.String(instanceArn),
			NextToken:   nextToken,
		})
		if err != nil {
			return newAgents, findings, fmt.Errorf("ListPermissionSets: %w", err)
		}

		for _, psArn := range listOut.PermissionSets {
			assigned := permissionSetHasAnyAssignment(ctx, client, instanceArn, psArn, orgAccountIDs)
			if assigned {
				continue
			}

			descOut, err := client.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
				InstanceArn:      aws.String(instanceArn),
				PermissionSetArn: aws.String(psArn),
			})
			name := psArn
			if err == nil && descOut.PermissionSet != nil {
				name = aws.ToString(descOut.PermissionSet.Name)
			}

			// Permission sets have no natural Lambda/ECS/Bedrock agent —
			// correlate by name first (e.g. "CrossAccountSyncAdmin" vs
			// "CrossAccountSync-Agent"), else synthesize a minimal record,
			// same precedent as the ExternalId check above.
			var agentStableID, agentName string
			if matched := matchAgentByName(name, knownAgents); matched != nil {
				agentStableID = matched.StableID
				agentName = matched.Name
			} else {
				sid := stableID(p.cfg.OrgID, psArn)
				agentStableID = sid
				agentName = name
				newAgents = append(newAgents, types.CanonicalAgentRecord{
					Name:             name,
					Platform:         "AWS_IDENTITY_CENTER_PERMISSION_SET",
					ExternalID:       psArn,
					StableID:         sid,
					OrgID:            p.cfg.OrgID,
					Region:           p.awsCfg.Region,
					LastSeenAt:       now,
					VisibilitySource: "SCANNER",
				})
			}

			evidence, _ := json.Marshal(map[string]string{
				"permissionSetArn": psArn,
				"instanceArn":      instanceArn,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "SSO_ORPHANED_PERMISSION_SET",
				Severity:      "MEDIUM",
				AgentStableID: agentStableID,
				AgentName:     agentName,
				Title:         "Identity Center permission set has no account assignments",
				Description: fmt.Sprintf(
					"Permission set %s is provisioned but assigned to zero users or groups across any account in the organization.",
					name,
				),
				EvidenceJSON: evidence,
				DiscoveredAt: now,
				Plugin:       "aws",
			})
		}

		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	return newAgents, findings, nil
}

// findSSOInstanceARN returns the first available Identity Center instance
// ARN. MVP assumption: a single org has a single Identity Center instance,
// matching AWS's own default topology.
func findSSOInstanceARN(ctx context.Context, client *ssoadmin.Client) (string, error) {
	out, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return "", fmt.Errorf("ListInstances: %w", err)
	}
	if len(out.Instances) == 0 {
		return "", nil
	}
	return aws.ToString(out.Instances[0].InstanceArn), nil
}

// permissionSetHasAnyAssignment checks ListAccountAssignments for psArn
// against every account in orgAccountIDs, returning true on the first
// non-empty result. ListAccountAssignments requires a per-account call —
// there is no org-wide "assignments for this permission set" API.
func permissionSetHasAnyAssignment(ctx context.Context, client *ssoadmin.Client, instanceArn, psArn string, orgAccountIDs []string) bool {
	for _, accountID := range orgAccountIDs {
		out, err := client.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			InstanceArn:      aws.String(instanceArn),
			AccountId:        aws.String(accountID),
			PermissionSetArn: aws.String(psArn),
		})
		if err != nil {
			continue
		}
		if isAssigned(out.AccountAssignments) {
			return true
		}
	}
	return false
}

// isAssigned reports whether a ListAccountAssignments result counts as
// "this permission set has a real assignment in this account".
func isAssigned(assignments []ssoadmintypes.AccountAssignment) bool {
	return len(assignments) > 0
}
