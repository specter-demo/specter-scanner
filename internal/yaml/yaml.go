// Package yaml implements the YAML agent import format (spec section 10).
// It parses specter-agent-import.yaml into []CanonicalAgentRecord.
package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	goyaml "gopkg.in/yaml.v3"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// AgentImportFile represents the top-level specter-agent-import.yaml structure.
type AgentImportFile struct {
	Version string        `yaml:"version"`
	OrgID   string        `yaml:"orgId"`
	Agents  []AgentImport `yaml:"agents"`
}

// AgentImport is a single agent entry in the import file.
type AgentImport struct {
	Name            string `yaml:"name"`
	Platform        string `yaml:"platform"`
	ExternalID      string `yaml:"externalId"`
	OwnerTag        string `yaml:"ownerTag"`
	AgentClassTag   string `yaml:"agentClassTag"`
	Framework       string `yaml:"framework"`
	IAMRoleARN      string `yaml:"iamRoleArn"`
	PublicURL       string `yaml:"publicUrl"`
	A2ACardURL      string `yaml:"a2aCardUrl"`
	FunctionalClass string `yaml:"functionalClass"`
}

// ParseFile reads a specter-agent-import.yaml file and returns agent records.
func ParseFile(path string) ([]types.CanonicalAgentRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("yaml: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads a specter-agent-import.yaml from an io.Reader and returns agent records.
func Parse(r io.Reader) ([]types.CanonicalAgentRecord, error) {
	var importFile AgentImportFile
	dec := goyaml.NewDecoder(r)
	if err := dec.Decode(&importFile); err != nil {
		return nil, fmt.Errorf("yaml: decode: %w", err)
	}

	now := time.Now().UTC()
	var agents []types.CanonicalAgentRecord

	for _, a := range importFile.Agents {
		agent := types.CanonicalAgentRecord{
			Name:             a.Name,
			Platform:         a.Platform,
			ExternalID:       a.ExternalID,
			OrgID:            importFile.OrgID,
			OwnerTag:         a.OwnerTag,
			AgentClassTag:    a.AgentClassTag,
			Framework:        a.Framework,
			IAMRoleARN:       a.IAMRoleARN,
			PublicURL:        a.PublicURL,
			A2ACardURL:       a.A2ACardURL,
			LastSeenAt:       now,
			VisibilitySource: "YAML_IMPORT",
		}

		// Compute stable ID
		agent.StableID = stableID(importFile.OrgID, a.ExternalID)

		// Map functional class string
		switch a.FunctionalClass {
		case "CONFIRMED_ORCHESTRATOR":
			agent.FunctionalClass = types.FunctionalClassConfirmedOrchestrator
		case "LIKELY_ORCHESTRATOR":
			agent.FunctionalClass = types.FunctionalClassLikelyOrchestrator
		case "WORKER":
			agent.FunctionalClass = types.FunctionalClassWorker
		case "EPHEMERAL":
			agent.FunctionalClass = types.FunctionalClassEphemeral
		case "MCP_SERVER":
			agent.FunctionalClass = types.FunctionalClassMCPServer
		}

		agents = append(agents, agent)
	}

	return agents, nil
}

func stableID(orgID, externalID string) string {
	h := sha256.Sum256([]byte(orgID + "|" + externalID))
	return hex.EncodeToString(h[:])[:16]
}
