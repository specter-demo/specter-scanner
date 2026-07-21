// Copyright 2026 Specter Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package plugin defines the ScanPlugin interface and ActivityStreamAdapter.
// All plugin implementations live in internal/plugin/<name>/.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ErrNotSupported is returned by streaming methods in MVP (batch-only mode).
var ErrNotSupported = errors.New("not supported in MVP")

// AuthError is returned by a plugin's Scan method when the plugin could not
// authenticate at all (expired/missing/invalid credentials), as distinct
// from a successful scan that simply found zero results. The caller (the
// scanner's main loop) uses this to decide whether a report should be
// written: a clean empty scan is valid and gets a report; a total
// authentication failure must not produce one (see allPluginsFailed in
// cmd/scanner/main.go).
type AuthError struct {
	PluginName string
	Err        error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: authentication failed: %v", e.PluginName, e.Err)
}

func (e *AuthError) Unwrap() error { return e.Err }

// PluginConfig contains the configuration for a plugin instance.
type PluginConfig struct {
	OrgID      string
	OrgSlug    string
	PluginType string
	RawConfig  []byte // decrypted plugin-specific config from platform

	// SeedAgents is the set of agents already discovered by earlier plugins in the
	// same scan. The GitHub plugin uses this to match repositories to known agents
	// and enrich them, rather than creating standalone GITHUB-platform records.
	// Populated by runScan() after Phase 1 (non-GitHub) plugins complete.
	SeedAgents []types.CanonicalAgentRecord

	// SeedEdges is the set of edges already discovered by earlier plugins in the
	// same scan. The GitHub plugin uses these to check for outbound A2A and
	// STATIC_REF edges when computing behavioral alignment scores.
	// Populated by runScan() after Phase 1 (non-GitHub) plugins complete.
	SeedEdges []types.AgentEdgeRecord
}

// ScanResult is returned by a plugin's Scan method.
type ScanResult struct {
	Agents     []types.CanonicalAgentRecord
	Edges      []types.AgentEdgeRecord
	Events     []types.NormalizedEvent // for chain reconstruction
	Findings   []types.FindingRecord   // plugin-level findings
	StaticRefs []types.StaticRef       // for static reference analysis (Phase 11.5)

	// ConfirmedHumanPrincipals optionally maps a principal ID (e.g. an
	// assumed-role ARN) to true when a platform-specific authoritative
	// source (AWS IAM Identity Center, for the AWS plugin) has confirmed
	// that principal is human. Passed through to chain.Reconstruct to
	// override its own CloudTrail-based inference for that principal. Most
	// plugins leave this nil, same as Events.
	ConfirmedHumanPrincipals map[string]bool
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
