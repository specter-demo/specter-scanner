// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package config handles scanner configuration: CLI flags, env vars, and
// platform config pull.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SuppressedFinding is a finding that the platform has suppressed via governance action.
// The scanner must not generate this finding for this agent.
type SuppressedFinding struct {
	AgentExternalID string    `json:"agentExternalId"`
	RuleID          string    `json:"ruleId"`
	SuppressedBy    string    `json:"suppressedBy"`
	SuppressedAt    time.Time `json:"suppressedAt"`
}

// PlatformConfig is the response from GET /api/v1/scanner/config.
type PlatformConfig struct {
	OrgID               string              `json:"orgId"`
	SigningKey           string              `json:"signingKey"`
	ScanIntervalMinutes int                 `json:"scanIntervalMinutes"`
	Plugins             []PluginConfig      `json:"plugins"`
	SuppressedFindings  []SuppressedFinding `json:"suppressedFindings"`
}

// IsSuppressed returns true when the platform has suppressed this finding for this agent.
func (pc *PlatformConfig) IsSuppressed(agentExternalID, ruleID string) bool {
	if pc == nil {
		return false
	}
	for _, sf := range pc.SuppressedFindings {
		if sf.AgentExternalID == agentExternalID && sf.RuleID == ruleID {
			return true
		}
	}
	return false
}

// PluginConfig represents one plugin entry in the platform config response.
type PluginConfig struct {
	PluginType string                 `json:"pluginType"`
	Status     string                 `json:"status"`
	Config     map[string]interface{} `json:"config"`
}

// RawConfig marshals the plugin's Config map to JSON bytes for passing to plugin.Configure.
func (p PluginConfig) RawConfig() ([]byte, error) {
	return json.Marshal(p.Config)
}

// FindPlugin returns the first CONNECTED plugin matching pluginType, or nil.
func (pc *PlatformConfig) FindPlugin(pluginType string) *PluginConfig {
	for i := range pc.Plugins {
		if strings.EqualFold(pc.Plugins[i].PluginType, pluginType) &&
			pc.Plugins[i].Status == "CONNECTED" {
			return &pc.Plugins[i]
		}
	}
	return nil
}

// FetchPlatformConfig fetches the scanner config from the platform API.
func FetchPlatformConfig(platformURL, apiKey string) (*PlatformConfig, error) {
	if platformURL == "" || apiKey == "" {
		return nil, fmt.Errorf("platform URL and API key required")
	}
	req, err := http.NewRequest(http.MethodGet, platformURL+"/api/v1/scanner/config", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch platform config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("platform config returned %d: %s", resp.StatusCode, string(body))
	}

	var cfg PlatformConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode platform config: %w", err)
	}
	return &cfg, nil
}

// ReadonlyRoleARN returns the cross-account SpecterReadOnly role ARN from the
// environment. Set via SPECTER_READONLY_ROLE_ARN in cloud-hosted ECS mode.
func ReadonlyRoleARN() string { return os.Getenv("SPECTER_READONLY_ROLE_ARN") }

// ReadonlyExternalID returns the STS ExternalId required by the SpecterReadOnly
// trust policy. Set via SPECTER_READONLY_EXTERNAL_ID in cloud-hosted ECS mode.
func ReadonlyExternalID() string { return os.Getenv("SPECTER_READONLY_EXTERNAL_ID") }

// ScannerConfig holds the runtime configuration for the scanner.
type ScannerConfig struct {
	// Platform API
	APIKey      string
	PlatformURL string

	// Mode flags
	NoPlatform   bool
	OutputFormat string // "json" | "html"
	OutputFile   string // output file path (standalone mode)
	PluginFilter string // run only this plugin

	// Scan parameters
	Since     time.Duration
	RateLimit int
	LogLevel  string

	// Standalone mode org config (used when --no-platform)
	OrgID   string
	OrgSlug string

	// AWS (standalone mode)
	AWSProfile string
	AWSRegion  string

	// GitHub (standalone mode)
	GitHubOrg   string
	GitHubToken string

	// Build-time version (set by -ldflags)
	Version string
}

// Parse parses CLI flags and environment variables.
func Parse() *ScannerConfig {
	cfg := &ScannerConfig{}

	flag.StringVar(&cfg.APIKey, "api-key", os.Getenv("SPECTER_API_KEY"), "Org API key")
	flag.StringVar(&cfg.PlatformURL, "platform-url", platformURL(), "Platform API base URL")
	flag.BoolVar(&cfg.NoPlatform, "no-platform", false, "Standalone mode: write report to file, no ingest")
	flag.StringVar(&cfg.OutputFormat, "output", "html", "Output format in standalone mode: html|json")
	flag.StringVar(&cfg.OutputFile, "output-file", "", "Output file path in standalone mode (default: specter-report.html or specter-report.json)")
	flag.StringVar(&cfg.PluginFilter, "plugin", "", "Run only this plugin: aws|github|mcp|a2a")
	flag.DurationVar(&cfg.Since, "since", 6*time.Hour, "How far back to look in audit logs")
	flag.IntVar(&cfg.RateLimit, "rate-limit", 10, "Protocol probe requests per second per endpoint")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "debug|info|warn|error")
	flag.StringVar(&cfg.OrgSlug, "org-slug", "", "Org slug for cross-org A2A checks (required for cross-org edge detection)")
	flag.StringVar(&cfg.AWSRegion, "aws-region", "us-east-1", "AWS region to scan (standalone mode)")
	flag.StringVar(&cfg.GitHubOrg, "github-org", "", "GitHub org to scan (required for GitHub plugin)")

	flag.Parse()

	// Environment overrides
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("SPECTER_API_KEY")
	}
	cfg.AWSProfile = os.Getenv("AWS_PROFILE")
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}

	// OrgID for stableId computation must match the platform's real org ID.
	// In cloud-hosted ECS mode, set SPECTER_ORG_ID to the platform org's UUID.
	// Falls back to the API key for backward-compat in standalone mode.
	cfg.OrgID = os.Getenv("SPECTER_ORG_ID")
	if cfg.OrgID == "" {
		cfg.OrgID = cfg.APIKey
	}
	if cfg.OrgID == "" {
		cfg.OrgID = "demo-org"
	}

	return cfg
}

func platformURL() string {
	if v := os.Getenv("SPECTER_PLATFORM_URL"); v != "" {
		return v
	}
	return "https://app.spectersystems.ai"
}
