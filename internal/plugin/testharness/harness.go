// Package testharness provides mock implementations for testing plugins.
package testharness

import (
	"context"
	"time"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// MockPlugin is a mock ScanPlugin for testing.
type MockPlugin struct {
	NameVal         string
	ScanResult      *plugin.ScanResult
	ScanErr         error
	HealthCheckErr  error
	ConfigureErr    error
}

// NewMockPlugin creates a MockPlugin that returns the provided ScanResult.
func NewMockPlugin(name string, result *plugin.ScanResult) *MockPlugin {
	return &MockPlugin{
		NameVal:    name,
		ScanResult: result,
	}
}

func (m *MockPlugin) Name() string { return m.NameVal }

func (m *MockPlugin) Configure(_ plugin.PluginConfig) error {
	return m.ConfigureErr
}

func (m *MockPlugin) Scan(_ context.Context) (*plugin.ScanResult, error) {
	if m.ScanErr != nil {
		return nil, m.ScanErr
	}
	if m.ScanResult != nil {
		return m.ScanResult, nil
	}
	return &plugin.ScanResult{}, nil
}

func (m *MockPlugin) HealthCheck(_ context.Context) error {
	return m.HealthCheckErr
}

// MockAgent builds a test CanonicalAgentRecord for use in tests.
func MockAgent(name, platform, stableID string) types.CanonicalAgentRecord {
	return types.CanonicalAgentRecord{
		Name:             name,
		Platform:         platform,
		StableID:         stableID,
		ExternalID:       platform + ":" + name,
		OrgID:            "test-org",
		LastSeenAt:       time.Now().UTC(),
		VisibilitySource: "TEST",
	}
}

// MockFinding builds a test FindingRecord.
func MockFinding(ruleID, severity, agentStableID, agentName string) types.FindingRecord {
	return types.FindingRecord{
		RuleID:        ruleID,
		Severity:      severity,
		AgentStableID: agentStableID,
		AgentName:     agentName,
		Title:         "Test finding: " + ruleID,
		Description:   "Mock finding for testing purposes.",
		DiscoveredAt:  time.Now().UTC(),
		Plugin:        "test",
	}
}

// MockEdge builds a test AgentEdgeRecord.
func MockEdge(sourceID, targetID string, edgeType types.EdgeType) types.AgentEdgeRecord {
	return types.AgentEdgeRecord{
		SourceStableID: sourceID,
		TargetStableID: targetID,
		EdgeType:       edgeType,
		Confidence:     0.9,
		DiscoveredAt:   time.Now().UTC(),
	}
}

// MockActivityAdapter is a mock ActivityStreamAdapter for testing.
type MockActivityAdapter struct {
	Events []types.NormalizedEvent
	FetchErr error
}

func (m *MockActivityAdapter) FetchEvents(_ context.Context, _ time.Time) ([]types.NormalizedEvent, error) {
	if m.FetchErr != nil {
		return nil, m.FetchErr
	}
	return m.Events, nil
}

func (m *MockActivityAdapter) StreamEvents(_ context.Context, _ chan<- types.NormalizedEvent) error {
	return plugin.ErrNotSupported
}

func (m *MockActivityAdapter) SupportsStreaming() bool { return false }
