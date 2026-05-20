// Package a2a implements the A2A protocol analyzer.
// It probes /.well-known/agent-card.json on agents with A2ACardURL set.
package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// Version is the A2A spec version this analyzer targets.
const Version = "1.0"

// Analyzer implements the A2A protocol analysis pass.
type Analyzer struct {
	client    *http.Client
	scanID    string
	rateLimit int // requests per second
	version   string
}

// ProtocolFinding extends FindingRecord with protocol-specific fields.
type ProtocolFinding struct {
	types.FindingRecord
	Protocol    string `json:"protocol"`
	SpecVersion string `json:"specVersion"`
	CheckID     string `json:"checkId"`
	Passed      bool   `json:"passed"`
	RiskModifier int   `json:"riskModifier"`
}

// New creates a new A2A Analyzer.
func New(scanID string, rateLimit int) *Analyzer {
	if scanID == "" {
		scanID = uuid.New().String()
	}
	if rateLimit <= 0 {
		rateLimit = 10
	}
	return &Analyzer{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		scanID:    scanID,
		rateLimit: rateLimit,
		version:   Version,
	}
}

func (a *Analyzer) Name() string    { return "a2a" }
func (a *Analyzer) Version() string { return a.version }

func (a *Analyzer) SelfTest(_ context.Context) error {
	return nil
}

// Analyze probes A2A endpoints and returns findings.
func (a *Analyzer) Analyze(ctx context.Context, agents []types.CanonicalAgentRecord, orgSlug string) ([]types.FindingRecord, error) {
	// Rate limiter: 10 req/s
	ticker := time.NewTicker(time.Second / time.Duration(a.rateLimit))
	defer ticker.Stop()

	var allFindings []types.FindingRecord

	for i := range agents {
		agent := &agents[i]
		if agent.A2ACardURL == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		case <-ticker.C:
		}

		findings := a.analyzeAgent(ctx, agent, orgSlug)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (a *Analyzer) analyzeAgent(ctx context.Context, agent *types.CanonicalAgentRecord, orgSlug string) []types.FindingRecord {
	now := time.Now().UTC()
	var findings []types.FindingRecord

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agent.A2ACardURL, nil)
	if err != nil {
		log.Printf("a2a: build request for %s: %v", agent.A2ACardURL, err)
		return findings
	}
	req.Header.Set("User-Agent", fmt.Sprintf("specter-scanner/%s (scanID=%s)", Version, a.scanID))

	resp, err := a.client.Do(req)
	if err != nil {
		// Network error → unreachable
		evidence, _ := json.Marshal(map[string]string{
			"url":   agent.A2ACardURL,
			"error": err.Error(),
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "A2A_CARD_UNREACHABLE",
			Severity:      "MEDIUM",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "A2A agent card unreachable",
			Description:   fmt.Sprintf("Could not fetch A2A card from %s: %v", agent.A2ACardURL, err),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "a2a",
		})
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		evidence, _ := json.Marshal(map[string]interface{}{
			"url":        agent.A2ACardURL,
			"statusCode": resp.StatusCode,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "A2A_CARD_UNREACHABLE",
			Severity:      "MEDIUM",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "A2A agent card unreachable",
			Description:   fmt.Sprintf("A2A card at %s returned HTTP %d.", agent.A2ACardURL, resp.StatusCode),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "a2a",
		})
		return findings
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return findings
	}

	var card types.A2ACard
	if err := json.Unmarshal(body, &card); err != nil {
		return findings
	}
	card.Raw = body
	agent.A2ACard = &card

	// Check 2: Signature
	sig := resp.Header.Get("X-Specter-Signature")
	if sig == "" && !card.Signed {
		evidence, _ := json.Marshal(map[string]string{
			"url":    agent.A2ACardURL,
			"signed": "false",
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "A2A_CARD_SIGNED",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "A2A agent card is not signed",
			Description:   fmt.Sprintf("Agent card at %s has no signature (card.signed=false, no X-Specter-Signature header).", agent.A2ACardURL),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "a2a",
		})
	} else {
		agent.A2ACardSigned = true
	}

	// Check 3: Authentication scheme
	if len(card.Authentication.Schemes) == 0 || containsNone(card.Authentication.Schemes) {
		evidence, _ := json.Marshal(map[string]interface{}{
			"url":     agent.A2ACardURL,
			"schemes": card.Authentication.Schemes,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "A2A_AUTH_NONE",
			Severity:      "CRITICAL",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "A2A agent card has no authentication",
			Description:   fmt.Sprintf("Agent card at %s has authentication.schemes=%v (no authentication required).", agent.A2ACardURL, card.Authentication.Schemes),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "a2a",
		})
	}

	// Check 4: Cross-org check
	if card.Provider.Organization != "" && card.Provider.Organization != orgSlug {
		evidence, _ := json.Marshal(map[string]string{
			"url":               agent.A2ACardURL,
			"cardOrg":           card.Provider.Organization,
			"scannerOrg":        orgSlug,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "A2A_CROSS_ORG",
			Severity:      "CRITICAL",
			AgentStableID: agent.StableID,
			AgentName:     agent.Name,
			Title:         "A2A agent card is from a different organization",
			Description:   fmt.Sprintf("Agent card organization %q does not match scanner org %q.", card.Provider.Organization, orgSlug),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "a2a",
		})
	}

	// Check 5: Wildcard capability
	for _, cap := range card.Capabilities {
		if cap == "*" {
			evidence, _ := json.Marshal(map[string]interface{}{
				"url":          agent.A2ACardURL,
				"capabilities": card.Capabilities,
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "A2A_WILDCARD_CAPABILITY",
				Severity:      "HIGH",
				AgentStableID: agent.StableID,
				AgentName:     agent.Name,
				Title:         "A2A agent card declares wildcard capability",
				Description:   fmt.Sprintf("Agent card at %s includes \"*\" in capabilities.", agent.A2ACardURL),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "a2a",
			})
			break
		}
	}

	return findings
}

func containsNone(schemes []string) bool {
	for _, s := range schemes {
		if strings.EqualFold(s, "none") {
			return true
		}
	}
	return false
}

// RiskModifier returns the risk modifier for a given A2A rule ID.
func RiskModifier(ruleID string) int {
	switch ruleID {
	case "A2A_AUTH_NONE":
		return 15
	case "A2A_CARD_SIGNED":
		return 10
	case "A2A_CROSS_ORG":
		return 20
	case "A2A_WILDCARD_CAPABILITY":
		return 10
	default:
		return 0
	}
}
