// Package activity provides types and wrappers for the ActivityStreamAdapter.
package activity

import (
	"context"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// Adapter is an interface for plugins that can fetch audit log events.
// This wraps the plugin.ActivityStreamAdapter with additional metadata.
type Adapter interface {
	// FetchEvents returns normalized events since the given time.
	FetchEvents(ctx context.Context, since time.Time) ([]types.NormalizedEvent, error)

	// StreamEvents is V2 only. Returns an error in MVP.
	StreamEvents(ctx context.Context, ch chan<- types.NormalizedEvent) error

	// SupportsStreaming returns false in MVP for all plugins.
	SupportsStreaming() bool
}

// AggregatedAdapter fans out FetchEvents calls across multiple adapters
// and merges the results.
type AggregatedAdapter struct {
	adapters []Adapter
}

// NewAggregated creates an AggregatedAdapter from multiple adapters.
func NewAggregated(adapters ...Adapter) *AggregatedAdapter {
	return &AggregatedAdapter{adapters: adapters}
}

// FetchEvents fetches events from all adapters and returns the merged list.
func (a *AggregatedAdapter) FetchEvents(ctx context.Context, since time.Time) ([]types.NormalizedEvent, error) {
	var all []types.NormalizedEvent
	for _, adapter := range a.adapters {
		events, err := adapter.FetchEvents(ctx, since)
		if err != nil {
			continue // log but continue
		}
		all = append(all, events...)
	}
	return all, nil
}

// StreamEvents is not supported in MVP.
func (a *AggregatedAdapter) StreamEvents(_ context.Context, _ chan<- types.NormalizedEvent) error {
	return errNotSupported
}

// SupportsStreaming returns false in MVP.
func (a *AggregatedAdapter) SupportsStreaming() bool { return false }

type notSupportedError struct{}

func (notSupportedError) Error() string { return "streaming not supported in MVP" }

var errNotSupported = notSupportedError{}
