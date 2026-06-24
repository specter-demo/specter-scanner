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
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	goyaml "gopkg.in/yaml.v3"
)

// SuppressedFinding is a finding that the platform has suppressed via governance action.
// The scanner must not generate this finding for this agent.
type SuppressedFinding struct {
	AgentExternalID string    `json:"agentExternalId"`
	RuleID          string    `json:"ruleId"`
	SuppressedBy    string    `json:"suppressedBy"`
	SuppressedAt    time.Time `json:"suppressedAt"`
}

// ExternalAgent is an agent the platform operator has classified as UNREGISTERED
// (external cross-org dependency). The scanner excludes these from governance analysis.
type ExternalAgent struct {
	ExternalID string `json:"externalId"`
}

// PlatformConfig is the response from GET /api/v1/scanner/config.
type PlatformConfig struct {
	OrgID               string              `json:"orgId"`
	SigningKey           string              `json:"signingKey"`
	ScanIntervalMinutes int                 `json:"scanIntervalMinutes"`
	Plugins             []PluginConfig      `json:"plugins"`
	SuppressedFindings  []SuppressedFinding `json:"suppressedFindings"`
	ExternalAgents      []ExternalAgent     `json:"externalAgents"`
}

// IsExternal returns true when the platform has classified this agent as UNREGISTERED.
// Handles the "external:https://HOSTNAME" → "HOSTNAME" normalisation that the ingest
// route applies when deduplicating cross-org agents against the existing DB record.
func (pc *PlatformConfig) IsExternal(agentExternalID string) bool {
	if pc == nil {
		return false
	}
	// Normalise scanner ExternalIDs of the form "external:https://host.example.com/..."
	// to bare hostnames, matching the form stored in the platform DB.
	normalised := agentExternalID
	for _, prefix := range []string{"external:https://", "external:http://"} {
		if strings.HasPrefix(agentExternalID, prefix) {
			// Extract just the hostname (drop path, port, query)
			rest := strings.TrimPrefix(agentExternalID, prefix)
			if idx := strings.IndexAny(rest, "/:?"); idx >= 0 {
				rest = rest[:idx]
			}
			normalised = rest
			break
		}
	}
	for _, ea := range pc.ExternalAgents {
		if ea.ExternalID == normalised || ea.ExternalID == agentExternalID {
			return true
		}
	}
	return false
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
	AWSProfile  string
	AWSRegion   string
	AWSAccounts []string // from specter.yaml plugins.aws.accounts; no CLI flag equivalent
	AWSRoleARN  string   // from specter.yaml plugins.aws.role_arn; no CLI flag equivalent

	// GitHub (standalone mode)
	GitHubOrg   string
	GitHubToken string

	// Output filtering — from specter.yaml output.min_severity; no CLI flag equivalent
	MinSeverity string

	// ConfigFile is the path to the specter.yaml file actually loaded, or ""
	// if none was found/loaded.
	ConfigFile string

	// Build-time version (set by -ldflags)
	Version string
}

// FileConfig maps the specter.yaml schema (spec section 7.8.2). Example:
//
//	org_slug: "my-company"
//	plugins:
//	  aws:
//	    accounts: ["123456789012"]
//	    regions: ["us-east-1"]
//	    role_arn: "arn:aws:iam::123456789012:role/SecurityAudit"
//	  github:
//	    org: "my-company"
//	    token_env: "GITHUB_TOKEN"
//	output:
//	  format: html
//	  path: "./reports/scan-{date}.html"
//	  min_severity: medium
type FileConfig struct {
	// OrgSlug identifies the scanning org for cross-org checks (e.g. A2A_CROSS_ORG).
	// Equivalent to --org-slug; the CLI flag always takes precedence if passed.
	OrgSlug string `yaml:"org_slug"`

	Plugins struct {
		AWS struct {
			Accounts []string `yaml:"accounts"`
			Regions  []string `yaml:"regions"`
			RoleARN  string   `yaml:"role_arn"`
		} `yaml:"aws"`
		GitHub struct {
			Org      string `yaml:"org"`
			TokenEnv string `yaml:"token_env"`
		} `yaml:"github"`
	} `yaml:"plugins"`
	Output struct {
		Format      string `yaml:"format"`
		Path        string `yaml:"path"`
		MinSeverity string `yaml:"min_severity"`
	} `yaml:"output"`
}

// loadFileConfig reads and parses a specter.yaml file. Returns (nil, nil) if
// the file does not exist — absence is not an error, since flags-only mode
// must work without any config file present.
func loadFileConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var fc FileConfig
	if err := goyaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &fc, nil
}

// expandDatePlaceholder replaces a literal "{date}" token in an output path
// with the current UTC date in YYYY-MM-DD form.
func expandDatePlaceholder(path string) string {
	return strings.ReplaceAll(path, "{date}", time.Now().UTC().Format("2006-01-02"))
}

// Parse parses CLI flags, a specter.yaml config file, and environment variables.
//
// Merge order: the YAML config file (if present) is loaded first and supplies
// values for anything the user didn't explicitly pass on the command line.
// CLI flags always win when explicitly set — the file never overrides a flag
// the user actually typed. Fields with no CLI flag equivalent (AWS accounts,
// AWS role ARN, output min_severity) come from the file unconditionally.
func Parse() *ScannerConfig {
	cfg := &ScannerConfig{}

	var configPath string
	flag.StringVar(&configPath, "config", "specter.yaml", "Path to specter.yaml config file (optional; flags always override file values)")
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

	// flag.Visit only visits flags the user actually set on the command line —
	// this is how we know whether a flag should override the file value.
	explicitFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

	// Load specter.yaml. Absence is not an error — flags-only mode must work
	// whether or not a config file exists. A malformed file is logged and
	// ignored rather than aborting the scan.
	fileCfg, err := loadFileConfig(configPath)
	if err != nil {
		if explicitFlags["config"] {
			log.Printf("[config] WARNING: could not load %s: %v — continuing with flags only", configPath, err)
		} else {
			log.Printf("[config] no config file at %s — continuing with flags only", configPath)
		}
		fileCfg = nil
	}

	githubTokenEnv := "GITHUB_TOKEN"

	if fileCfg != nil {
		cfg.ConfigFile = configPath
		log.Printf("[config] loaded %s", configPath)

		if !explicitFlags["org-slug"] && fileCfg.OrgSlug != "" {
			cfg.OrgSlug = fileCfg.OrgSlug
			log.Printf("[config] org_slug from file: %s", cfg.OrgSlug)
		}

		if !explicitFlags["aws-region"] && len(fileCfg.Plugins.AWS.Regions) > 0 {
			cfg.AWSRegion = fileCfg.Plugins.AWS.Regions[0]
			log.Printf("[config] aws.regions from file: %v (using %s)", fileCfg.Plugins.AWS.Regions, cfg.AWSRegion)
		}
		cfg.AWSAccounts = fileCfg.Plugins.AWS.Accounts
		cfg.AWSRoleARN = fileCfg.Plugins.AWS.RoleARN

		if !explicitFlags["github-org"] && fileCfg.Plugins.GitHub.Org != "" {
			cfg.GitHubOrg = fileCfg.Plugins.GitHub.Org
			log.Printf("[config] github.org from file: %s", cfg.GitHubOrg)
		}
		if fileCfg.Plugins.GitHub.TokenEnv != "" {
			githubTokenEnv = fileCfg.Plugins.GitHub.TokenEnv
		}

		if !explicitFlags["output"] && fileCfg.Output.Format != "" {
			cfg.OutputFormat = fileCfg.Output.Format
		}
		if !explicitFlags["output-file"] && fileCfg.Output.Path != "" {
			cfg.OutputFile = expandDatePlaceholder(fileCfg.Output.Path)
		}
		cfg.MinSeverity = fileCfg.Output.MinSeverity
	}

	// Environment overrides
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("SPECTER_API_KEY")
	}
	cfg.AWSProfile = os.Getenv("AWS_PROFILE")
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = os.Getenv(githubTokenEnv)
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

	// If OrgID fell all the way through to the literal "demo-org" placeholder
	// and the user supplied an org_slug (file or flag), use that instead — it's
	// a real, human-meaningful identifier and is what should appear in the
	// standalone report header rather than a generic placeholder.
	if cfg.OrgID == "demo-org" && cfg.OrgSlug != "" {
		cfg.OrgID = cfg.OrgSlug
	}

	return cfg
}

func platformURL() string {
	if v := os.Getenv("SPECTER_PLATFORM_URL"); v != "" {
		return v
	}
	return "https://app.spectersystems.ai"
}
