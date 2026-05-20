// Package types defines all shared data structures used across the specter-scanner.
// These types form the ingest contract between the scanner and the platform.
package types

import (
	"encoding/json"
	"time"
)

// VisibilityClass describes how well governed an agent is.
type VisibilityClass string

const (
	VisibilityClassGoverned     VisibilityClass = "GOVERNED"
	VisibilityClassDiscovered   VisibilityClass = "DISCOVERED"
	VisibilityClassShadow       VisibilityClass = "SHADOW"
	VisibilityClassUnregistered VisibilityClass = "UNREGISTERED"
)

// FunctionalClass describes what role an agent plays in the system.
type FunctionalClass string

const (
	FunctionalClassConfirmedOrchestrator FunctionalClass = "CONFIRMED_ORCHESTRATOR"
	FunctionalClassLikelyOrchestrator    FunctionalClass = "LIKELY_ORCHESTRATOR"
	FunctionalClassWorker                FunctionalClass = "WORKER"
	FunctionalClassEphemeral             FunctionalClass = "EPHEMERAL"
	FunctionalClassMCPServer             FunctionalClass = "MCP_SERVER"
)

// FederationStatus describes how the agent's identity is federated.
type FederationStatus string

const (
	FederationStatusNotFederated         FederationStatus = "NOT_FEDERATED"
	FederationStatusPartiallyFederated   FederationStatus = "PARTIALLY_FEDERATED"
	FederationStatusFullyFederated       FederationStatus = "FULLY_FEDERATED"
	FederationStatusUnregistered         FederationStatus = "UNREGISTERED"
)

// RiskTier classifies blast radius severity.
type RiskTier string

const (
	RiskTierCritical RiskTier = "CRITICAL"
	RiskTierHigh     RiskTier = "HIGH"
	RiskTierMedium   RiskTier = "MEDIUM"
	RiskTierLow      RiskTier = "LOW"
)

// EdgeType describes the relationship between two agents.
type EdgeType string

const (
	EdgeTypeSTSAssume    EdgeType = "STS_ASSUME"
	EdgeTypeECSSpawn     EdgeType = "ECS_SPAWN"
	EdgeTypeOIDCDeploy   EdgeType = "OIDC_DEPLOY"
	EdgeTypeA2ACall      EdgeType = "A2A_CALL"
	EdgeTypePartnerAgent EdgeType = "PARTNER_AGENT"
	EdgeTypeEnvURL       EdgeType = "ENV_URL"
)

// A2ACard is the parsed agent card from the A2A protocol.
type A2ACard struct {
	SchemaVersion  string          `json:"schemaVersion"`
	ProtocolVersion string         `json:"protocolVersion"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Provider       A2AProvider     `json:"provider"`
	Authentication A2AAuth         `json:"authentication"`
	Capabilities   []string        `json:"capabilities"`
	Signed         bool            `json:"signed"`
	Version        string          `json:"version"`
	Raw            json.RawMessage `json:"-"`
}

// A2AProvider contains provider/org info from the A2A card.
type A2AProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url"`
}

// A2AAuth contains authentication info from the A2A card.
type A2AAuth struct {
	Schemes []string `json:"schemes"`
}

// MCPManifest represents a parsed MCP server manifest.
type MCPManifest struct {
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Auth    MCPAuth `json:"auth"`
	Tools   []MCPTool `json:"tools"`
}

// MCPAuth represents the authentication config in an MCP manifest.
type MCPAuth struct {
	Type              string   `json:"type"`
	TokenValidation   bool     `json:"tokenValidation"`
	PKCERequired      bool     `json:"pkceRequired"`
	ResourceIndicator *string  `json:"resourceIndicator"`
	Scopes            []string `json:"scopes"`
}

// MCPTool represents a tool entry in an MCP manifest.
type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// EphemeralSignal is evidence of an inferred ephemeral sub-agent.
type EphemeralSignal struct {
	InferredFromPrincipal string        `json:"inferredFromPrincipal"`
	ParentAgentARN        string        `json:"parentAgentArn"`
	BurstStart            time.Time     `json:"burstStart"`
	EventCount            int           `json:"eventCount"`
	InferredLifetime      time.Duration `json:"inferredLifetimeMs"`
}

// CanonicalAgentRecord is the normalized representation of a discovered agent.
// One record per agent, per scan. Posted in the ingest payload.
type CanonicalAgentRecord struct {
	// Identity
	StableID   string `json:"stableId"`
	OrgID      string `json:"orgId"`
	ExternalID string `json:"externalId"` // ARN, GitHub repo path, etc.

	// Discovery metadata
	Name            string    `json:"name"`
	Platform        string    `json:"platform"` // "AWS_LAMBDA" | "AWS_ECS" | "AWS_BEDROCK" | "GITHUB" | "EXTERNAL_HTTP"
	AccountID       string    `json:"accountId,omitempty"`
	Region          string    `json:"region,omitempty"`
	PublicURL       string    `json:"publicUrl,omitempty"`
	FirstSeenAt     *time.Time `json:"firstSeenAt,omitempty"` // nil = first scan
	LastSeenAt      time.Time  `json:"lastSeenAt"`

	// Framework detection (Classification section 6.1)
	Framework           string  `json:"framework,omitempty"`
	FrameworkConfidence float64 `json:"frameworkConfidence,omitempty"`

	// Classification dimensions
	VisibilityClass VisibilityClass `json:"visibilityClass"`
	FunctionalClass FunctionalClass `json:"functionalClass"`
	FederationStatus FederationStatus `json:"federationStatus"`

	// Boolean shortcuts
	IsShadow   bool `json:"isShadow"`
	IsEphemeral bool `json:"isEphemeral"`

	// Governance
	OwnerTag       string  `json:"ownerTag,omitempty"`
	AgentClassTag  string  `json:"agentClassTag,omitempty"`
	LastReviewedAt *time.Time `json:"lastReviewedAt,omitempty"`

	// IAM
	IAMRoleARN       string     `json:"iamRoleArn,omitempty"`
	IAMRoleCreatedAt *time.Time `json:"iamRoleCreatedAt,omitempty"`
	CreatedByIAMUser string     `json:"createdByIamUser,omitempty"`
	CreatedByIAMAt   *time.Time `json:"createdByIamAt,omitempty"`

	// Permissions
	IAMPermissions []NormalizedPermission `json:"iamPermissions,omitempty"`
	HasWildcard    bool                   `json:"hasWildcard"`

	// Function URL config (Lambda)
	FunctionURLAuthType string `json:"functionUrlAuthType,omitempty"`
	FunctionURL         string `json:"functionUrl,omitempty"`
	APIGatewayURL       string `json:"apiGatewayUrl,omitempty"`

	// Protocol
	A2ACard       *A2ACard    `json:"a2aCard,omitempty"`
	A2ACardSigned bool        `json:"a2aCardSigned"`
	A2ACardURL    string      `json:"a2aCardUrl,omitempty"`
	MCPManifest   *MCPManifest `json:"mcpManifest,omitempty"`

	// Risk
	RiskScore    int      `json:"riskScore"`
	BlastRadius  *BlastRadiusRecord `json:"blastRadius,omitempty"`

	// Ephemeral sub-agent signals
	EphemeralSignals []EphemeralSignal `json:"ephemeralSignals,omitempty"`

	// Environment variables (Lambda/ECS) — used for classification
	// Never forwarded raw: only framework detection signals are recorded
	EnvFrameworkSignals []string          `json:"envFrameworkSignals,omitempty"`
	EnvMCPConfig        map[string]string `json:"envMcpConfig,omitempty"` // MCP-specific env vars
	EnvExternalURLs     map[string]string `json:"envExternalUrls,omitempty"` // discovered external agent URLs

	// Visibility source
	VisibilitySource string `json:"visibilitySource,omitempty"` // "SCANNER" | "TIER_2"
}

// AgentEdgeRecord represents a relationship between two agents.
type AgentEdgeRecord struct {
	SourceStableID string   `json:"sourceStableId"`
	TargetStableID string   `json:"targetStableId"`
	EdgeType       EdgeType `json:"edgeType"`
	Confidence     float64  `json:"confidence"`
	DiscoveredAt   time.Time `json:"discoveredAt"`
	Evidence       string    `json:"evidence,omitempty"`
}

// NormalizedPermission maps platform-specific actions to normalized ops.
type NormalizedPermission struct {
	Op            string `json:"op"`            // "storage.read" | "secret.read" | "agent.invoke" | etc.
	ResourceScope string `json:"resourceScope"` // "*" | "arn:..." | specific resource
	Platform      string `json:"platform"`
	RawAction     string `json:"rawAction"` // e.g. "s3:GetObject"
}

// NormalizedCredential describes the credential type used by an agent.
type NormalizedCredential struct {
	Type        string `json:"type"`        // "SHORT_LIVED_ROLE" | "SERVICE_ACCOUNT" | etc.
	Platform    string `json:"platform"`
	RawType     string `json:"rawType"`
	Description string `json:"description"`
}

// FindingRecord represents a security finding discovered by the scanner.
type FindingRecord struct {
	RuleID       string          `json:"ruleId"`       // e.g. "IAM_WILDCARD_RESOURCE"
	Severity     string          `json:"severity"`     // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
	AgentStableID string         `json:"agentStableId"`
	AgentName    string          `json:"agentName"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	EvidenceJSON json.RawMessage `json:"evidenceJson,omitempty"`
	DiscoveredAt time.Time       `json:"discoveredAt"`
	Plugin       string          `json:"plugin"` // "aws" | "github" | "a2a" | "mcp"
}

// NormalizedEvent is a normalized audit log event from any cloud platform.
type NormalizedEvent struct {
	EventID         string    `json:"eventId"`
	Timestamp       time.Time `json:"timestamp"`
	Principal       Principal `json:"principal"`
	Action          string    `json:"action"`         // normalized: "storage.read", "secret.read"
	PlatformAction  string    `json:"platformAction"` // raw: "s3:GetObject"
	Resource        Resource  `json:"resource"`
	Outcome         string    `json:"outcome"` // "SUCCESS" | "FAILURE" | "DENIED"
	SourcePlatform  string    `json:"sourcePlatform"`
	SourceRegion    string    `json:"sourceRegion"`
	CredentialType  string    `json:"credentialType"`
	RFC8693Present  bool      `json:"rfc8693Present"`
	OnBehalfOf      string    `json:"onBehalfOf,omitempty"`
	SessionID       string    `json:"sessionId,omitempty"`
	CorrelationID   string    `json:"correlationId"`

	// Extra CloudTrail fields used for chain reconstruction
	AssumedRoleARN  string `json:"assumedRoleArn,omitempty"`
	CallerARN       string `json:"callerArn,omitempty"`
}

// Principal is the identity that performed an action.
type Principal struct {
	ID   string `json:"id"`   // ARN, email, username
	Type string `json:"type"` // "HUMAN" | "AGENT" | "SCHEDULER" | "API_KEY" | "WEBHOOK" | "SYSTEM" | "EVENT"
	Name string `json:"name"`
}

// Resource is the target of an action.
type Resource struct {
	ID       string `json:"id"`
	Type     string `json:"type"`     // "s3_bucket" | "lambda_function" | "secret" | etc.
	Platform string `json:"platform"`
	Region   string `json:"region"`
}

// DelegationChainRecord represents a reconstructed causal chain of agent actions.
type DelegationChainRecord struct {
	ChainID                 string          `json:"chainId"`
	RootAgentStableID       string          `json:"rootAgentStableId"`
	RootPrincipalType       string          `json:"rootPrincipalType"`
	RootIntent              string          `json:"rootIntent"`
	Hops                    []DelegationHop `json:"hops"`
	ChainBreakAt            *int            `json:"chainBreakAt,omitempty"` // hop index where RFC8693 breaks
	IsUnattended            bool            `json:"isUnattended"`
	RFC8693Compliant        bool            `json:"rfc8693Compliant"`
	ReconstructionConfidence float64        `json:"reconstructionConfidence"`
	PartialChain            bool            `json:"partialChain"`
	ReconstructedAt         time.Time       `json:"reconstructedAt"`
}

// DelegationHop is a single step in a delegation chain.
type DelegationHop struct {
	AgentStableID string   `json:"agentStableId"`
	EdgeType      EdgeType `json:"edgeType"`
	RFC8693       bool     `json:"rfc8693"`
	ScopeAtHop    string   `json:"scopeAtHop,omitempty"`
}

// BlastRadiusRecord captures the computed blast radius for an agent.
type BlastRadiusRecord struct {
	Tier                RiskTier               `json:"tier"`
	Score               int                    `json:"score"`
	UniquePermissions   int                    `json:"uniquePermissions"`
	MaxDataScope        string                 `json:"maxDataScope"` // "ACCOUNT_WIDE" | "MULTI_SERVICE" | "SINGLE_SERVICE" | "NARROW"
	ReachableAgentIDs   []string               `json:"reachableAgentIds"`
	ReachableServices   []string               `json:"reachableServices"`
	CrossOrgEdges       []string               `json:"crossOrgEdges"`
	NormalizedPermissions []NormalizedPermission `json:"normalizedPermissions,omitempty"`
	ComputedAt          time.Time              `json:"computedAt"`
}

// ScanPayload is the full payload posted to the platform ingest endpoint.
type ScanPayload struct {
	ScanID        string                 `json:"scanId"`
	OrgID         string                 `json:"orgId"`
	ScannerVersion string               `json:"scannerVersion"`
	ScannedAt     time.Time              `json:"scannedAt"`
	Agents        []CanonicalAgentRecord `json:"agents"`
	Edges         []AgentEdgeRecord      `json:"edges"`
	Findings      []FindingRecord        `json:"findings"`
	Chains        []DelegationChainRecord `json:"chains"`
}
