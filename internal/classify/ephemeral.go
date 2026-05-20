package classify

import (
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// EphemeralClassification holds the result of ephemeral agent detection.
type EphemeralClassification struct {
	IsEphemeral      bool
	InferredLifetime time.Duration
	ParentStableID   string
	Signals          []types.EphemeralSignal
}

// ClassifyEphemeral determines if an agent is ephemeral based on
// its EphemeralSignals and behavioral patterns.
func ClassifyEphemeral(agent *types.CanonicalAgentRecord) EphemeralClassification {
	if len(agent.EphemeralSignals) == 0 {
		return EphemeralClassification{IsEphemeral: false}
	}

	var totalLifetime time.Duration
	var parentStableID string

	for _, sig := range agent.EphemeralSignals {
		totalLifetime += sig.InferredLifetime
		if parentStableID == "" && sig.ParentAgentARN != "" {
			parentStableID = sig.ParentAgentARN
		}
	}

	avgLifetime := totalLifetime
	if len(agent.EphemeralSignals) > 0 {
		avgLifetime = totalLifetime / time.Duration(len(agent.EphemeralSignals))
	}

	isEphemeral := avgLifetime < 5*time.Minute

	return EphemeralClassification{
		IsEphemeral:      isEphemeral,
		InferredLifetime: avgLifetime,
		ParentStableID:   parentStableID,
		Signals:          agent.EphemeralSignals,
	}
}
