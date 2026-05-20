// Package mcp implements the MCP protocol analyzer (spec 2025-06-18).
// It checks MCP server agents for OAuth, PKCE, resource indicator,
// and scope configuration issues.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

const specVersion = "2025-06-18"

// Analyzer implements MCP protocol analysis.
type Analyzer struct {
	client *http.Client
}

// New creates a new MCP Analyzer.
func New() *Analyzer {
	return &Analyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *Analyzer) Name() string    { return "mcp" }
func (a *Analyzer) Version() string { return specVersion }
func (a *Analyzer) SelfTest(_ context.Context) error { return nil }

// Analyze runs MCP compliance checks against all MCP server agents.
func (a *Analyzer) Analyze(ctx context.Context, agents []types.CanonicalAgentRecord, _ string) ([]types.FindingRecord, error) {
	var allFindings []types.FindingRecord

	for i := range agents {
		agent := &agents[i]
		if agent.FunctionalClass != types.FunctionalClassMCPServer && agent.AgentClassTag != "mcp-server" {
			continue
		}

		findings := a.analyzeAgent(ctx, agent)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (a *Analyzer) analyzeAgent(ctx context.Context, agent *types.CanonicalAgentRecord) []types.FindingRecord {
	now := time.Now().UTC()
	var findings []types.FindingRecord

	// Step 1: Try HTTP probe for EXTERNAL_HTTP agents
	var manifest *types.MCPManifest
	if agent.Platform == "EXTERNAL_HTTP" && agent.PublicURL != "" {
		mcpURL := strings.TrimRight(agent.PublicURL, "/") + "/.well-known/mcp.json"
		manifest = a.probeMCPEndpoint(ctx, mcpURL)
	}

	// Step 2: If HTTP probe not available, fall back to ENV VARS
	if manifest == nil && len(agent.EnvMCPConfig) > 0 {
		findings = append(findings, a.analyzeEnvConfig(agent, now)...)
		return findings
	}

	// Step 3: Analyze HTTP manifest if fetched
	if manifest != nil {
		agent.MCPManifest = manifest
		findings = append(findings, a.analyzeManifest(agent, manifest, now)...)
	}

	return findings
}

func (a *Analyzer) probeMCPEndpoint(ctx context.Context, url string) *types.MCPManifest {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("mcp: probe %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	var manifest types.MCPManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil
	}
	return &manifest
}

func (a *Analyzer) analyzeEnvConfig(agent *types.CanonicalAgentRecord, now time.Time) []types.FindingRecord {
	var findings []types.FindingRecord
	cfg := agent.EnvMCPConfig

	// OAUTH_ENABLED=true + OAUTH_VALIDATE=false → MCP_OAUTH_DISABLED
	if cfg["OAUTH_ENABLED"] == "true" && cfg["OAUTH_VALIDATE"] == "false" {
		evidence, _ := json.Marshal(map[string]string{
			"OAUTH_ENABLED":   cfg["OAUTH_ENABLED"],
			"OAUTH_VALIDATE":  cfg["OAUTH_VALIDATE"],
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_OAUTH_DISABLED",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP OAuth is enabled but token validation is disabled",
			Description:   fmt.Sprintf("MCP server %s has OAUTH_ENABLED=true but OAUTH_VALIDATE=false, bypassing token validation.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// PKCE_REQUIRED=false → MCP_NO_PKCE
	if cfg["PKCE_REQUIRED"] == "false" {
		evidence, _ := json.Marshal(map[string]string{
			"PKCE_REQUIRED": cfg["PKCE_REQUIRED"],
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_NO_PKCE",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP server does not require PKCE",
			Description:   fmt.Sprintf("MCP server %s has PKCE_REQUIRED=false, making it vulnerable to authorization code interception.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// RESOURCE_INDICATOR=false → MCP_NO_RESOURCE_INDICATOR
	if cfg["RESOURCE_INDICATOR"] == "false" {
		evidence, _ := json.Marshal(map[string]string{
			"RESOURCE_INDICATOR": cfg["RESOURCE_INDICATOR"],
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_NO_RESOURCE_INDICATOR",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP server does not use resource indicators",
			Description:   fmt.Sprintf("MCP server %s has RESOURCE_INDICATOR=false, allowing token confusion attacks.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// TOOL_SCOPE=* → MCP_WILDCARD_SCOPE
	if cfg["TOOL_SCOPE"] == "*" {
		evidence, _ := json.Marshal(map[string]string{
			"TOOL_SCOPE": cfg["TOOL_SCOPE"],
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_WILDCARD_SCOPE",
			Severity:      "MEDIUM",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP server uses wildcard tool scope",
			Description:   fmt.Sprintf("MCP server %s has TOOL_SCOPE=*, granting access to all tools without explicit scope restrictions.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	return findings
}

func (a *Analyzer) analyzeManifest(agent *types.CanonicalAgentRecord, manifest *types.MCPManifest, now time.Time) []types.FindingRecord {
	var findings []types.FindingRecord

	// OAuth token validation disabled
	if manifest.Auth.Type == "oauth" && !manifest.Auth.TokenValidation {
		evidence, _ := json.Marshal(map[string]interface{}{
			"authType":        manifest.Auth.Type,
			"tokenValidation": manifest.Auth.TokenValidation,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_OAUTH_DISABLED",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP OAuth token validation is disabled",
			Description:   fmt.Sprintf("MCP server %s manifest shows OAuth auth type but tokenValidation=false.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// PKCE not required
	if manifest.Auth.Type == "oauth" && !manifest.Auth.PKCERequired {
		evidence, _ := json.Marshal(map[string]bool{
			"pkceRequired": manifest.Auth.PKCERequired,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_NO_PKCE",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP server does not require PKCE",
			Description:   fmt.Sprintf("MCP server %s manifest shows pkceRequired=false.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// No resource indicator
	if manifest.Auth.ResourceIndicator != nil && *manifest.Auth.ResourceIndicator == "" {
		evidence, _ := json.Marshal(map[string]string{
			"resourceIndicator": "",
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "MCP_NO_RESOURCE_INDICATOR",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "MCP server does not use resource indicators",
			Description:   fmt.Sprintf("MCP server %s manifest has empty resourceIndicator.", agent.Name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "mcp",
		})
	}

	// Wildcard scope
	for _, scope := range manifest.Auth.Scopes {
		if scope == "*" {
			evidence, _ := json.Marshal(map[string][]string{
				"scopes": manifest.Auth.Scopes,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "MCP_WILDCARD_SCOPE",
				Severity:      "MEDIUM",
				AgentStableID: agent.StableID,
				AgentName:     agent.Name,
				Title:         "MCP server uses wildcard scope",
				Description:   fmt.Sprintf("MCP server %s manifest includes \"*\" in auth scopes.", agent.Name),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "mcp",
			})
			break
		}
	}

	return findings
}
