package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

func makeAgent(name, cardURL string) types.CanonicalAgentRecord {
	return types.CanonicalAgentRecord{
		StableID:   "test-stable-id-" + name,
		Name:       name,
		A2ACardURL: cardURL,
		LastSeenAt: time.Now(),
	}
}

func TestA2ACardUnreachable(t *testing.T) {
	// Serve HTTP 403
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	analyzer := New("test-scan", 100)
	agents := []types.CanonicalAgentRecord{
		makeAgent("test-agent", srv.URL+"/.well-known/agent-card.json"),
	}

	findings, err := analyzer.Analyze(context.Background(), agents, "test-org")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.RuleID == "A2A_CARD_UNREACHABLE" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected A2A_CARD_UNREACHABLE finding, got findings: %+v", findings)
	}
}

func TestA2AAuthNone(t *testing.T) {
	card := types.A2ACard{
		Name:           "test-agent",
		Authentication: types.A2AAuth{Schemes: []string{"none"}},
		Provider:       types.A2AProvider{Organization: "test-org"},
		Signed:         false,
	}
	body, _ := json.Marshal(card)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	analyzer := New("test-scan", 100)
	agents := []types.CanonicalAgentRecord{
		makeAgent("test-agent", srv.URL+"/.well-known/agent-card.json"),
	}

	findings, err := analyzer.Analyze(context.Background(), agents, "test-org")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.RuleID == "A2A_AUTH_NONE" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected A2A_AUTH_NONE finding, got: %+v", findings)
	}
}

func TestA2ACrossOrg(t *testing.T) {
	card := types.A2ACard{
		Name:           "meridian-agent",
		Authentication: types.A2AAuth{Schemes: []string{"bearer"}},
		Provider:       types.A2AProvider{Organization: "meridian-data"},
		Signed:         true,
	}
	body, _ := json.Marshal(card)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Specter-Signature", "sha256=abc123")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	analyzer := New("test-scan", 100)
	agents := []types.CanonicalAgentRecord{
		makeAgent("meridian-agent", srv.URL+"/.well-known/agent-card.json"),
	}

	findings, err := analyzer.Analyze(context.Background(), agents, "specter-demo")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.RuleID == "A2A_CROSS_ORG" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected A2A_CROSS_ORG finding, got: %+v", findings)
	}
}

func TestA2AWildcardCapability(t *testing.T) {
	card := types.A2ACard{
		Name:           "wild-agent",
		Authentication: types.A2AAuth{Schemes: []string{"bearer"}},
		Provider:       types.A2AProvider{Organization: "test-org"},
		Capabilities:   []string{"read", "*", "write"},
		Signed:         true,
	}
	body, _ := json.Marshal(card)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Specter-Signature", "sha256=abc123")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	analyzer := New("test-scan", 100)
	agents := []types.CanonicalAgentRecord{
		makeAgent("wild-agent", srv.URL+"/.well-known/agent-card.json"),
	}

	findings, err := analyzer.Analyze(context.Background(), agents, "test-org")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.RuleID == "A2A_WILDCARD_CAPABILITY" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected A2A_WILDCARD_CAPABILITY finding, got: %+v", findings)
	}
}

func TestRiskModifier(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected int
	}{
		{"A2A_AUTH_NONE", 15},
		{"A2A_CARD_SIGNED", 10},
		{"A2A_CROSS_ORG", 20},
		{"A2A_WILDCARD_CAPABILITY", 10},
		{"UNKNOWN", 0},
	}
	for _, tt := range tests {
		if got := RiskModifier(tt.ruleID); got != tt.expected {
			t.Errorf("RiskModifier(%q) = %d, want %d", tt.ruleID, got, tt.expected)
		}
	}
}
