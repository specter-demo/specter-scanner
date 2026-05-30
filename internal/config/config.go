// Package config handles scanner configuration: CLI flags, env vars, and
// platform config pull.
package config

import (
	"flag"
	"os"
	"time"
)

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
	flag.BoolVar(&cfg.NoPlatform, "no-platform", false, "Standalone mode: write report to stdout, no ingest")
	flag.StringVar(&cfg.OutputFormat, "output", "html", "Output format in standalone mode: json|html")
	flag.StringVar(&cfg.PluginFilter, "plugin", "", "Run only this plugin: aws|github|mcp|a2a")
	flag.DurationVar(&cfg.Since, "since", 6*time.Hour, "How far back to look in audit logs")
	flag.IntVar(&cfg.RateLimit, "rate-limit", 10, "Protocol probe requests per second per endpoint")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "debug|info|warn|error")
	flag.StringVar(&cfg.OrgSlug, "org-slug", "specter-demo", "Org slug for cross-org checks (standalone mode)")
	flag.StringVar(&cfg.AWSRegion, "aws-region", "us-east-1", "AWS region to scan (standalone mode)")
	flag.StringVar(&cfg.GitHubOrg, "github-org", "specter-demo", "GitHub org to scan (standalone mode)")

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
