// Package sdk provides exported types for third-party plugin authors.
// It re-exports the key types from internal/plugin and internal/types.
package sdk

import (
	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// ScanPlugin is the interface that all Specter scanner plugins must implement.
// Third-party plugins should embed or implement this interface.
type ScanPlugin = plugin.ScanPlugin

// PluginConfig is passed to the Configure method of each plugin.
type PluginConfig = plugin.PluginConfig

// ScanResult is returned by the Scan method.
type ScanResult = plugin.ScanResult

// CanonicalAgentRecord is the normalized agent representation.
type CanonicalAgentRecord = types.CanonicalAgentRecord

// FindingRecord represents a security finding.
type FindingRecord = types.FindingRecord

// AgentEdgeRecord represents a relationship between two agents.
type AgentEdgeRecord = types.AgentEdgeRecord

// NormalizedEvent is a normalized audit log event.
type NormalizedEvent = types.NormalizedEvent

// NormalizedPermission maps platform-specific actions to normalized ops.
type NormalizedPermission = types.NormalizedPermission

// ScanPayload is the full payload posted to the platform.
type ScanPayload = types.ScanPayload

// EdgeType describes the relationship between two agents.
type EdgeType = types.EdgeType

// VisibilityClass describes how well governed an agent is.
type VisibilityClass = types.VisibilityClass

// FunctionalClass describes what role an agent plays.
type FunctionalClass = types.FunctionalClass

// RiskTier classifies blast radius severity.
type RiskTier = types.RiskTier

// Constants re-exported for plugin authors.
const (
	EdgeTypeSTSAssume    = types.EdgeTypeSTSAssume
	EdgeTypeECSSpawn     = types.EdgeTypeECSSpawn
	EdgeTypeOIDCDeploy   = types.EdgeTypeOIDCDeploy
	EdgeTypeA2ACall      = types.EdgeTypeA2ACall
	EdgeTypePartnerAgent = types.EdgeTypePartnerAgent
	EdgeTypeEnvURL       = types.EdgeTypeEnvURL

	VisibilityClassGoverned     = types.VisibilityClassGoverned
	VisibilityClassDiscovered   = types.VisibilityClassDiscovered
	VisibilityClassShadow       = types.VisibilityClassShadow
	VisibilityClassUnregistered = types.VisibilityClassUnregistered

	FunctionalClassConfirmedOrchestrator = types.FunctionalClassConfirmedOrchestrator
	FunctionalClassLikelyOrchestrator    = types.FunctionalClassLikelyOrchestrator
	FunctionalClassWorker                = types.FunctionalClassWorker
	FunctionalClassEphemeral             = types.FunctionalClassEphemeral
	FunctionalClassMCPServer             = types.FunctionalClassMCPServer

	RiskTierCritical = types.RiskTierCritical
	RiskTierHigh     = types.RiskTierHigh
	RiskTierMedium   = types.RiskTierMedium
	RiskTierLow      = types.RiskTierLow
)

// Register registers a third-party plugin with the Specter scanner.
// Call this from your plugin's init() function.
var Register = plugin.Register

// ErrNotSupported is returned by streaming methods in MVP (batch-only mode).
var ErrNotSupported = plugin.ErrNotSupported
