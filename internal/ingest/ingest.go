// Package ingest assembles scan payloads and computes HMAC signatures
// for posting to the Specter platform (spec section 11).
package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// Assemble builds a ScanPayload from the collected scan results.
// stableID = sha256(orgID + "|" + externalID)[:16]
func Assemble(
	scanID string,
	orgID string,
	scannerVersion string,
	agents []types.CanonicalAgentRecord,
	edges []types.AgentEdgeRecord,
	findings []types.FindingRecord,
	chains []types.DelegationChainRecord,
) types.ScanPayload {
	return types.ScanPayload{
		ScanID:         scanID,
		OrgID:          orgID,
		ScannerVersion: scannerVersion,
		ScannedAt:      time.Now().UTC(),
		Agents:         agents,
		Edges:          edges,
		Findings:       findings,
		Chains:         chains,
	}
}

// StableID computes the stable cross-scan identifier for an agent.
// Format: sha256(orgID + "|" + externalID)[:16]
func StableID(orgID, externalID string) string {
	h := sha256.Sum256([]byte(orgID + "|" + externalID))
	return hex.EncodeToString(h[:])[:16]
}

// Sign computes an HMAC-SHA256 signature over the payload bytes.
// Returns "sha256=" + hex(hmac-sha256(payload, key))
func Sign(payload []byte, signingKey string) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Marshal serializes a ScanPayload to JSON.
func Marshal(payload types.ScanPayload) ([]byte, error) {
	return json.Marshal(payload)
}

// MarshalSigned serializes a ScanPayload and returns JSON + signature.
func MarshalSigned(payload types.ScanPayload, signingKey string) ([]byte, string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("ingest: marshal payload: %w", err)
	}
	sig := Sign(data, signingKey)
	return data, sig, nil
}
