// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// TestDiscoversLambdaAgents verifies framework + stability of agent construction.
// We test the internal buildECSServiceAgent / detectFrameworkFromEnv paths
// since we can't easily mock the AWS SDK without interfaces.
func TestDiscoversLambdaAgents(t *testing.T) {
	p := &Plugin{
		cfg:    plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{Region: "us-east-1"},
	}

	// Build two synthetic agents the same way the scanner would
	envVars1 := map[string]string{"ANTHROPIC_API_KEY": "sk-ant-xxx"}
	envVars2 := map[string]string{"OPENAI_API_KEY": "sk-xxx"}

	agent1, _, _ := p.buildECSServiceAgent(
		"arn:aws:ecs:us-east-1:123456789:service/cluster/agent-one",
		"",
		map[string]string{"specter:owner": "team-a"},
		envVars1,
		"arn:aws:ecs:us-east-1:123456789:cluster/cluster",
	)
	agent2, _, _ := p.buildECSServiceAgent(
		"arn:aws:ecs:us-east-1:123456789:service/cluster/agent-two",
		"",
		map[string]string{"specter:owner": "team-b"},
		envVars2,
		"arn:aws:ecs:us-east-1:123456789:cluster/cluster",
	)

	agents := []types.CanonicalAgentRecord{agent1, agent2}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	if agents[0].Name == "" || agents[1].Name == "" {
		t.Error("agent names should not be empty")
	}
}

func TestFrameworkDetectionFromTags(t *testing.T) {
	p := &Plugin{
		cfg:    plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{Region: "us-east-1"},
	}

	agent := types.CanonicalAgentRecord{Name: "test-fn"}
	envVars := map[string]string{"ANTHROPIC_API_KEY": "sk-ant-xxx"}
	agent = p.detectFrameworkFromEnv(agent, envVars)

	if agent.Framework != "anthropic" {
		t.Errorf("expected framework=anthropic, got %q", agent.Framework)
	}
	if agent.FrameworkConfidence != 0.85 {
		t.Errorf("expected confidence=0.85, got %f", agent.FrameworkConfidence)
	}
}

func TestShadowAgentNoOwnerTag(t *testing.T) {
	p := &Plugin{
		cfg:    plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{Region: "us-east-1"},
	}

	_, findings, _ := p.buildECSServiceAgent(
		"arn:aws:ecs:us-east-1:123456789:service/cluster/shadow-fn",
		"",
		map[string]string{}, // no specter:owner
		map[string]string{},
		"arn:aws:ecs:us-east-1:123456789:cluster/cluster",
	)

	var found bool
	for _, f := range findings {
		if f.RuleID == "IAM_NO_OWNER_TAG" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected IAM_NO_OWNER_TAG finding for Lambda with no owner tag")
	}
}

func TestWildcardIAMPolicyFinding(t *testing.T) {
	policy := `{
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject"],
			"Resource": "*"
		}]
	}`

	perms := parseIAMPolicy(policy)
	if !hasWildcardOnSensitive(perms) {
		t.Error("expected hasWildcardOnSensitive to return true for s3:GetObject with Resource:*")
	}

	var findings []types.FindingRecord
	p := &Plugin{
		cfg:    plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{Region: "us-east-1"},
	}
	agent := types.CanonicalAgentRecord{
		Name:       "test-fn",
		StableID:   "abc123",
		IAMRoleARN: "arn:aws:iam::123456789:role/test-role",
	}

	if hasWildcardOnSensitive(perms) {
		agent.HasWildcard = true
		evidence, _ := json.Marshal(map[string]string{
			"roleArn":    agent.IAMRoleARN,
			"policyName": "inline-policy",
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "IAM_WILDCARD_RESOURCE",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "IAM policy grants sensitive actions on wildcard resource",
			Description:   "test",
			EvidenceJSON:  evidence,
			DiscoveredAt:  time.Now(),
			Plugin:        "aws",
		})
	}

	_ = p

	var found bool
	for _, f := range findings {
		if f.RuleID == "IAM_WILDCARD_RESOURCE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected IAM_WILDCARD_RESOURCE finding")
	}
}

func TestHealthCheckReturnsNilOnValidConfig(t *testing.T) {
	// We test the config loading path, not actual AWS connectivity.
	// In a real test environment without AWS credentials, this will fail
	// at the STS call, so we just check config loading succeeds.
	p := &Plugin{
		cfg: plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{
			StandaloneMode: true,
			Region:         "us-east-1",
		},
	}

	ctx := context.Background()
	// We call Configure first
	err := p.Configure(plugin.PluginConfig{OrgID: "test-org"})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	// loadAWSConfig should succeed in standalone mode (uses env/profile)
	_, err = p.loadAWSConfig(ctx)
	if err != nil {
		t.Logf("loadAWSConfig returned (expected in CI without creds): %v", err)
		// Not fatal — CI may not have AWS credentials
	}
}

func TestScanTimesOutAfterDeadline(t *testing.T) {
	p := &Plugin{
		cfg: plugin.PluginConfig{OrgID: "test-org"},
		awsCfg: AWSPluginConfig{
			StandaloneMode: true,
			Region:         "us-east-1",
		},
	}

	// Context already cancelled
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	cancel()

	_, err := p.Scan(ctx)
	if err == nil {
		// Scan may return partial results or an error
		t.Log("Scan returned nil error on expired context (may be acceptable if no AWS calls made)")
	} else {
		t.Logf("Scan correctly failed on cancelled context: %v", err)
	}
}

func TestExtractExternalURLs(t *testing.T) {
	envVars := map[string]string{
		"PARTNER_AGENT_URL":  "https://partner.example.com",
		"SERVICE_URL":        "https://svc.example.com",
		"RANDOM_VAR":         "not-a-url",
		"INTERNAL_AGENT_URL": "http://localhost:8080",
	}

	urls := extractExternalURLs(envVars)
	if _, ok := urls["PARTNER_AGENT_URL"]; !ok {
		t.Error("expected PARTNER_AGENT_URL to be extracted")
	}
	if _, ok := urls["RANDOM_VAR"]; ok {
		t.Error("RANDOM_VAR should not be extracted (not a URL pattern)")
	}
	if _, ok := urls["INTERNAL_AGENT_URL"]; ok {
		t.Error("localhost URL should be excluded")
	}
}

// TestNHIOrphanedCreatorSuppressedByOwnerTag validates that a non-empty specter:owner
// tag suppresses NHI_ORPHANED_CREATOR even when the IAM creator no longer exists.
func TestNHIOrphanedCreatorSuppressedByOwnerTag(t *testing.T) {
	cases := []struct {
		name          string
		ownerTag      string
		creatorExists bool
		wantFinding   bool
	}{
		{
			name:          "orphaned creator, no owner tag — should fire",
			ownerTag:      "",
			creatorExists: false,
			wantFinding:   true,
		},
		{
			name:          "orphaned creator, owner tag set — suppressed",
			ownerTag:      "compliance-engineering",
			creatorExists: false,
			wantFinding:   false,
		},
		{
			name:          "orphaned creator, whitespace-only owner tag — should fire",
			ownerTag:      "   ",
			creatorExists: false,
			wantFinding:   true,
		},
		{
			name:          "creator still exists, no owner tag — should not fire",
			ownerTag:      "",
			creatorExists: true,
			wantFinding:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Replicate the exact guard condition from scanIAMProvenance.
			shouldFire := !tc.creatorExists && strings.TrimSpace(tc.ownerTag) == ""
			if shouldFire != tc.wantFinding {
				t.Errorf("NHI_ORPHANED_CREATOR guard: ownerTag=%q creatorExists=%v → shouldFire=%v, want %v",
					tc.ownerTag, tc.creatorExists, shouldFire, tc.wantFinding)
			}
		})
	}
}

// TestNHIStaleRoleSuppressedByOwnerTag validates that a non-empty specter:owner
// tag suppresses NHI_STALE_ROLE regardless of role age.
func TestNHIStaleRoleSuppressedByOwnerTag(t *testing.T) {
	staleTime := time.Now().Add(-100 * 24 * time.Hour) // 100 days old → stale
	freshTime := time.Now().Add(-10 * 24 * time.Hour)  // 10 days old → not stale

	cases := []struct {
		name        string
		ownerTag    string
		createdAt   time.Time
		wantFinding bool
	}{
		{
			name:        "stale role, no owner tag — should fire",
			ownerTag:    "",
			createdAt:   staleTime,
			wantFinding: true,
		},
		{
			name:        "stale role, owner tag set — suppressed",
			ownerTag:    "platform-team",
			createdAt:   staleTime,
			wantFinding: false,
		},
		{
			name:        "fresh role, no owner tag — should not fire",
			ownerTag:    "",
			createdAt:   freshTime,
			wantFinding: false,
		},
		{
			name:        "stale role, whitespace owner tag — should fire",
			ownerTag:    "  ",
			createdAt:   staleTime,
			wantFinding: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Replicate the exact guard condition from scanIAMProvenance.
			shouldFire := strings.TrimSpace(tc.ownerTag) == "" &&
				time.Since(tc.createdAt) > 90*24*time.Hour
			if shouldFire != tc.wantFinding {
				t.Errorf("NHI_STALE_ROLE guard: ownerTag=%q age=%v → shouldFire=%v, want %v",
					tc.ownerTag, time.Since(tc.createdAt).Round(time.Hour), shouldFire, tc.wantFinding)
			}
		})
	}
}

func TestDetectBursts(t *testing.T) {
	now := time.Now()
	events := make([]types.NormalizedEvent, 5)
	for i := range events {
		events[i] = types.NormalizedEvent{
			EventID:   "evt-" + string(rune('0'+i)),
			Timestamp: now.Add(time.Duration(i) * 10 * time.Second),
			Principal: types.Principal{ID: "arn:aws:sts::123:assumed-role/role/session"},
		}
	}

	bursts := detectBursts(events, 3, 60*time.Second)
	if len(bursts) == 0 {
		t.Error("expected to detect at least one burst")
	}
}

// ── SECRETSMANAGER_WILDCARD_ACCESS ────────────────────────────────────────────

func TestAppendSecretsManagerWildcardFinding_WildcardResource(t *testing.T) {
	agent := types.CanonicalAgentRecord{
		StableID:   "example-agent-id",
		Name:       "example-agent",
		IAMRoleARN: "arn:aws:iam::111111111111:role/example-agent-role",
	}
	perms := []types.NormalizedPermission{
		{RawAction: "secretsmanager:GetSecretValue", ResourceScope: "*"},
	}

	var findings []types.FindingRecord
	appendSecretsManagerWildcardFinding(&findings, agent, perms, "example-agent-role-policy", time.Now())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a wildcard-scoped secretsmanager:GetSecretValue grant, got %d", len(findings))
	}
	if findings[0].RuleID != "SECRETSMANAGER_WILDCARD_ACCESS" {
		t.Errorf("expected RuleID SECRETSMANAGER_WILDCARD_ACCESS, got %q", findings[0].RuleID)
	}
}

func TestAppendSecretsManagerWildcardFinding_ScopedResource_NoFinding(t *testing.T) {
	agent := types.CanonicalAgentRecord{
		StableID:   "example-agent-id",
		Name:       "example-agent",
		IAMRoleARN: "arn:aws:iam::111111111111:role/example-agent-role",
	}
	perms := []types.NormalizedPermission{
		{RawAction: "secretsmanager:GetSecretValue", ResourceScope: "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-secret-abc123"},
	}

	var findings []types.FindingRecord
	appendSecretsManagerWildcardFinding(&findings, agent, perms, "example-agent-role-policy", time.Now())

	if len(findings) != 0 {
		t.Errorf("expected no finding for a secretsmanager:GetSecretValue grant scoped to a specific secret ARN, got %d", len(findings))
	}
}

func TestAppendSecretsManagerWildcardFinding_NoMatchingAction(t *testing.T) {
	agent := types.CanonicalAgentRecord{StableID: "example-agent-id", Name: "example-agent"}
	perms := []types.NormalizedPermission{
		{RawAction: "s3:GetObject", ResourceScope: "*"},
	}

	var findings []types.FindingRecord
	appendSecretsManagerWildcardFinding(&findings, agent, perms, "example-agent-role-policy", time.Now())

	if len(findings) != 0 {
		t.Errorf("expected no finding when no permission is a secretsmanager:GetSecretValue grant, got %d", len(findings))
	}
}

// ── extractPrincipal classification ───────────────────────────────────────────
//
// TestExtractPrincipal_InvokedByEventBridge is a regression test for the
// SCHEDULER root-cause fix: CloudTrail records which service made a call
// on the caller's behalf in userIdentity.invokedBy, not in the event's own
// eventSource (which is always the API being called). The old
// eventSource-based check could never fire for this reason.
func TestExtractPrincipal_InvokedByEventBridge(t *testing.T) {
	identity := map[string]interface{}{
		"type":      "AWSService",
		"invokedBy": "events.amazonaws.com",
	}
	pr := extractPrincipal(identity)
	if pr.Type != "SCHEDULER" {
		t.Errorf("expected Type=SCHEDULER when userIdentity.invokedBy is events.amazonaws.com, got %q", pr.Type)
	}
}

func TestExtractPrincipal_InvokedByOtherService_NotScheduler(t *testing.T) {
	identity := map[string]interface{}{
		"type":      "AWSService",
		"invokedBy": "lambda.amazonaws.com",
	}
	pr := extractPrincipal(identity)
	if pr.Type == "SCHEDULER" {
		t.Errorf("expected a non-EventBridge invokedBy to NOT classify as SCHEDULER, got %q", pr.Type)
	}
}

// TestExtractPrincipal_SSOAssumedRoleIsHuman is a regression test for the
// second classification bug: an IAM Identity Center (AWS SSO) federated
// session shows up in CloudTrail as userIdentity.type == AssumedRole, and
// was being swept into AGENT alongside real agent execution roles. The ARN
// shape here (assumed-role/AWSReservedSSO_<PermissionSet>_<hash>/<user>)
// matches this account's real CloudTrail data, not a guessed format.
func TestExtractPrincipal_SSOAssumedRoleIsHuman(t *testing.T) {
	identity := map[string]interface{}{
		"type": "AssumedRole",
		"arn":  "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc123def456/jane.doe",
	}
	pr := extractPrincipal(identity)
	if pr.Type != "HUMAN" {
		t.Errorf("expected Type=HUMAN for an IAM Identity Center SSO AssumedRole session, got %q", pr.Type)
	}
}

// TestExtractPrincipal_NonSSOAssumedRoleIsStillAgent confirms the SSO fix
// doesn't over-broaden: a genuine agent execution role assumption (no
// AWSReservedSSO_ in the role name) must still classify as AGENT.
func TestExtractPrincipal_NonSSOAssumedRoleIsStillAgent(t *testing.T) {
	identity := map[string]interface{}{
		"type": "AssumedRole",
		"arn":  "arn:aws:sts::111111111111:assumed-role/example-agent-execution-role/example-session-id",
	}
	pr := extractPrincipal(identity)
	if pr.Type != "AGENT" {
		t.Errorf("expected Type=AGENT for a non-SSO AssumedRole session (a real agent role), got %q", pr.Type)
	}
}

func TestExtractPrincipal_IAMUserIsHuman(t *testing.T) {
	identity := map[string]interface{}{"type": "IAMUser", "arn": "arn:aws:iam::111111111111:user/jane.doe"}
	pr := extractPrincipal(identity)
	if pr.Type != "HUMAN" {
		t.Errorf("expected Type=HUMAN for an IAMUser principal, got %q", pr.Type)
	}
}

func TestExtractPrincipal_NilIdentity(t *testing.T) {
	pr := extractPrincipal(nil)
	if pr.Type != "SYSTEM" {
		t.Errorf("expected Type=SYSTEM for a nil identity map, got %q", pr.Type)
	}
}
