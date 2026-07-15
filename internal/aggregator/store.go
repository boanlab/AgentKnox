// SPDX-License-Identifier: Apache-2.0

// Package aggregator is the AgentKnox central aggregator: it ingests event
// envelopes forwarded by daemons running on many hosts, persists them in a
// pluggable Store (bbolt for single-node/embedded, Postgres for shared/scale),
// and exposes a gRPC query API (AgentKnoxAggregator service).
//
// Daemons forward envelopes over the Ingest RPC, tagging the source node name.
// Each envelope becomes a stored Record.
package aggregator

import (
	"context"
	"encoding/json"
	"time"
)

// defaultQueryLimit caps a Query that does not request an explicit Limit.
const defaultQueryLimit = 1000

// Record is one persisted event: an envelope tagged with its source node. Data
// is the raw JSON payload of the envelope, stored verbatim so the aggregator is
// agnostic to the concrete event type behind each kind.
type Record struct {
	Source string          `json:"source"`
	Kind   string          `json:"kind"`
	Time   time.Time       `json:"time"`
	Data   json.RawMessage `json:"data"`
}

// Filter selects Records for Query. Empty string fields and a zero Since impose
// no constraint; a Limit of 0 falls back to defaultQueryLimit.
type Filter struct {
	Source string
	Kind   string
	Since  time.Time
	Limit  int
}

// limitOrDefault returns the effective query limit for f.
func (f Filter) limitOrDefault() int {
	if f.Limit <= 0 {
		return defaultQueryLimit
	}
	return f.Limit
}

// matches reports whether r satisfies f's Source/Kind/Since constraints. The
// Limit is applied by the caller during collection.
func (f Filter) matches(r Record) bool {
	if f.Source != "" && r.Source != f.Source {
		return false
	}
	if f.Kind != "" && r.Kind != f.Kind {
		return false
	}
	if !f.Since.IsZero() && r.Time.Before(f.Since) {
		return false
	}
	return true
}

// SourceStat summarises what the aggregator has stored for one source node.
type SourceStat struct {
	Source   string    `json:"source"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"lastSeen"`
}

// Store is the pluggable persistence backend for the aggregator.
type Store interface {
	// Put persists a batch of Records. An empty batch is a no-op.
	Put(ctx context.Context, recs []Record) error
	// Query returns matching Records newest-first, capped by f's limit.
	Query(ctx context.Context, f Filter) ([]Record, error)
	// Sources returns per-source counts and last-seen times.
	Sources(ctx context.Context) ([]SourceStat, error)
	// Prune deletes Records older than olderThan, returning the count removed.
	Prune(ctx context.Context, olderThan time.Time) (int64, error)
	// Close releases the backend's resources.
	Close() error
}
