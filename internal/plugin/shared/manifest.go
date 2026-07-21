// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package shared

import "gopkg.in/yaml.v3"

// SpecterManifest is the parsed shape of a .specter/manifest.yaml intent
// declaration. Any source-control plugin (GitHub, CodeCommit, GitLab, etc.)
// that can fetch a file's raw content can parse it with the same schema —
// the manifest format itself doesn't vary by platform.
type SpecterManifest struct {
	Specter struct {
		Agent struct {
			Intent       string   `yaml:"intent"`
			Owner        string   `yaml:"owner"`
			Capabilities []string `yaml:"capabilities"`
			// RiskAcknowledgements is a free-form map (handles_pii: true, etc.);
			// declared as map[string]interface{} to tolerate any value type.
			RiskAcknowledgements map[string]interface{} `yaml:"risk_acknowledgements"`
			Deployment           struct {
				Target      string `yaml:"target"`
				Status      string `yaml:"status"`
				Region      string `yaml:"region"`
				Environment string `yaml:"environment"`
			} `yaml:"deployment"`
		} `yaml:"agent"`
	} `yaml:"specter"`
	// Legacy flat fields for backward compatibility with manifests written
	// before the nested specter.agent.* schema.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Owner       string `yaml:"owner"`
}

// ParsedManifest is the subset of a SpecterManifest callers actually need,
// with the nested/legacy-field fallback already resolved.
type ParsedManifest struct {
	Intent           string
	Owner            string
	DeploymentTarget string
	DeploymentStatus string
}

// ParseSpecterManifest parses the raw content of a .specter/manifest.yaml
// file using real YAML decoding (not a hand-rolled line scanner — a
// customer's manifest can use any valid YAML formatting: multi-line
// strings, different indentation, comments, flow syntax, etc., and this
// must parse it the same way regardless of which plugin found the file).
//
// ok reflects only whether the content was valid YAML — it does NOT mean
// "an intent was found". A manifest can validly declare a
// deployment.target with no intent field at all, and callers need that
// distinction: check the returned ParsedManifest's individual fields for
// emptiness, don't treat ok==false as "nothing here".
func ParseSpecterManifest(content string) (ParsedManifest, bool) {
	var m SpecterManifest
	if err := yaml.Unmarshal([]byte(content), &m); err != nil {
		return ParsedManifest{}, false
	}

	intent := m.Specter.Agent.Intent
	owner := m.Specter.Agent.Owner
	// Fall back to legacy flat fields.
	if intent == "" {
		intent = m.Description
	}
	if owner == "" {
		owner = m.Owner
	}

	parsed := ParsedManifest{
		Intent:           intent,
		Owner:            owner,
		DeploymentTarget: m.Specter.Agent.Deployment.Target,
		DeploymentStatus: m.Specter.Agent.Deployment.Status,
	}
	return parsed, true
}
