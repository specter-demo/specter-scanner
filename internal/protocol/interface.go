// Package protocol defines the ProtocolAnalyzer interface.
package protocol

import (
	"context"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ProtocolAnalyzer analyzes agent protocol compliance (A2A, MCP, etc.).
type ProtocolAnalyzer interface {
	// Name returns the protocol name, e.g. "a2a" or "mcp".
	Name() string

	// Version returns the spec version being analyzed.
	Version() string

	// Analyze runs protocol checks against all agents.
	Analyze(ctx context.Context, agents []types.CanonicalAgentRecord, orgSlug string) ([]types.FindingRecord, error)

	// SelfTest validates the analyzer configuration and connectivity.
	SelfTest(ctx context.Context) error
}
