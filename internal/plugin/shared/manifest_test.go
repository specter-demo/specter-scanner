// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package shared

import "testing"

func TestParseSpecterManifest_ValidYAMLWithIntent(t *testing.T) {
	content := `
specter:
  agent:
    intent: "Processes incoming support tickets and drafts replies."
    owner: "team-support"
    deployment:
      target: "ecs"
      status: "active"
`
	parsed, ok := ParseSpecterManifest(content)
	if !ok {
		t.Fatal("expected valid YAML to parse successfully")
	}
	if parsed.Intent != "Processes incoming support tickets and drafts replies." {
		t.Errorf("expected Intent to be populated from specter.agent.intent, got %q", parsed.Intent)
	}
	if parsed.Owner != "team-support" {
		t.Errorf("expected Owner to be populated from specter.agent.owner, got %q", parsed.Owner)
	}
	if parsed.DeploymentTarget != "ecs" {
		t.Errorf("expected DeploymentTarget %q, got %q", "ecs", parsed.DeploymentTarget)
	}
}

// TestParseSpecterManifest_ValidYAMLWithoutIntentButWithDeploymentTarget is a
// regression test for the exact bug caught during live validation: an
// earlier draft of ParseSpecterManifest conflated "valid YAML" with "has an
// intent field" in its ok return value, so a manifest that validly declares
// deployment.target with no intent at all would have its DeploymentTarget
// silently dropped. ok must reflect only "valid YAML was parsed" — callers
// are responsible for checking Intent emptiness separately.
func TestParseSpecterManifest_ValidYAMLWithoutIntentButWithDeploymentTarget(t *testing.T) {
	content := `
specter:
  agent:
    deployment:
      target: "lambda"
      status: "active"
`
	parsed, ok := ParseSpecterManifest(content)
	if !ok {
		t.Fatal("expected valid YAML with no intent field to still report ok=true")
	}
	if parsed.Intent != "" {
		t.Errorf("expected empty Intent when no intent field is present, got %q", parsed.Intent)
	}
	if parsed.DeploymentTarget != "lambda" {
		t.Errorf("expected DeploymentTarget %q to be captured even though intent is absent, got %q", "lambda", parsed.DeploymentTarget)
	}
}

func TestParseSpecterManifest_LegacyFlatFieldsFallback(t *testing.T) {
	content := `
name: example-agent
description: "Legacy-format manifest description used as intent fallback."
owner: team-platform
`
	parsed, ok := ParseSpecterManifest(content)
	if !ok {
		t.Fatal("expected valid legacy-format YAML to parse successfully")
	}
	if parsed.Intent != "Legacy-format manifest description used as intent fallback." {
		t.Errorf("expected Intent to fall back to the legacy description field, got %q", parsed.Intent)
	}
	if parsed.Owner != "team-platform" {
		t.Errorf("expected Owner to fall back to the legacy owner field, got %q", parsed.Owner)
	}
}

func TestParseSpecterManifest_InvalidYAML(t *testing.T) {
	content := "specter:\n  agent: [unterminated flow sequence\n  intent: \"broken"
	parsed, ok := ParseSpecterManifest(content)
	if ok {
		t.Error("expected malformed YAML to report ok=false")
	}
	if parsed != (ParsedManifest{}) {
		t.Errorf("expected a zero-value ParsedManifest on parse failure, got %+v", parsed)
	}
}

func TestParseSpecterManifest_EmptyFile(t *testing.T) {
	parsed, ok := ParseSpecterManifest("")
	if !ok {
		t.Error("expected empty content to be treated as valid (empty) YAML, not a parse error")
	}
	if parsed != (ParsedManifest{}) {
		t.Errorf("expected a zero-value ParsedManifest for empty content, got %+v", parsed)
	}
}
