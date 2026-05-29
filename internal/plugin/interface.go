// Package plugin defines the ScanPlugin interface and ActivityStreamAdapter.
// All plugin implementations live in internal/plugin/<name>/.
package plugin

import (
	"context"
	"errors"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ErrNotSupported is returned by streaming methods in MVP (batch-only mode).
var ErrNotSupported = errors.New("not supported in MVP")

// PluginConfig contains the configuration for a plugin instance.
type PluginConfig struct {
	OrgID      string
	OrgSlug    string
	PluginType string
	RawConfig  []byte // decrypted plugin-specific config from platform
}

// ScanResult is returned by a plugin's Scan method.
type ScanResult struct {
	Agents     []types.CanonicalAgentRecord
	Edges      []types.AgentEdgeRecord
	Events     []types.NormalizedEvent // for chain reconstruction
	Findings   []types.FindingRecord   // plugin-level findings
	StaticRefs []types.StaticRef       // for static reference analysis (Phase 11.5)
}

// ScanPlugin is the interface every plugin must implement.
// All plugin implementations live in internal/plugin/<name>/.
type ScanPlugin interface {
	// Name returns the plugin identifier. Used in config and log output.
	Name() string // "aws" | "github" | "mcp" | "a2a"

	// Configure validates the plugin config and returns a ready plugin.
	// Called once at startup. Returns error if config is invalid.
	Configure(cfg PluginConfig) error

	// Scan discovers agents and returns records.
	// ctx carries a deadline set to the scan timeout (default 10 minutes).
	// Scan must be safe to call concurrently with other plugins.
	Scan(ctx context.Context) (*ScanResult, error)

	// HealthCheck tests the plugin's connection without running a full scan.
	// Called by the platform's test connection flow.
	HealthCheck(ctx context.Context) error
}

// ActivityStreamAdapter is implemented by plugins that read audit logs.
// The scanner calls FetchEvents to get historical events for chain
// reconstruction and ephemeral agent detection.
type ActivityStreamAdapter interface {
	// FetchEvents returns normalized events since the given time.
	// MVP: batch mode only. since is typically scanInterval (default 6h) ago.
	// Must paginate internally. Returns all events, not just the first page.
	FetchEvents(ctx context.Context, since time.Time) ([]types.NormalizedEvent, error)

	// StreamEvents is V2 only. Returns ErrNotSupported in MVP.
	StreamEvents(ctx context.Context, ch chan<- types.NormalizedEvent) error

	// SupportsStreaming returns false in MVP for all plugins.
	SupportsStreaming() bool
}
