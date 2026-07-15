// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestBolt opens a bolt store in a temp dir, closing it at test end.
func newTestBolt(t *testing.T) Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func rec(source, kind string, ts time.Time, payload string) Record {
	return Record{Source: source, Kind: kind, Time: ts, Data: json.RawMessage(payload)}
}

func TestBoltPutQuery(t *testing.T) {
	st := newTestBolt(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

	recs := []Record{
		rec("nodeA", "syscall", base.Add(1*time.Minute), `{"n":1}`),
		rec("nodeA", "alert", base.Add(2*time.Minute), `{"n":2}`),
		rec("nodeB", "syscall", base.Add(3*time.Minute), `{"n":3}`),
		rec("nodeB", "log", base.Add(4*time.Minute), `{"n":4}`),
	}
	if err := st.Put(ctx, recs); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Newest-first, no filter.
	got, err := st.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 records, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Time.Before(got[i].Time) {
			t.Fatalf("not newest-first at %d: %v before %v", i, got[i-1].Time, got[i].Time)
		}
	}
	if got[0].Data == nil || string(got[0].Data) != `{"n":4}` {
		t.Fatalf("newest record data mismatch: %s", got[0].Data)
	}

	// Source filter.
	got, _ = st.Query(ctx, Filter{Source: "nodeA"})
	if len(got) != 2 {
		t.Fatalf("source filter: want 2, got %d", len(got))
	}
	for _, r := range got {
		if r.Source != "nodeA" {
			t.Fatalf("source filter leaked %q", r.Source)
		}
	}

	// Kind filter.
	got, _ = st.Query(ctx, Filter{Kind: "syscall"})
	if len(got) != 2 {
		t.Fatalf("kind filter: want 2, got %d", len(got))
	}

	// Since filter (inclusive of >= base+3m => records 3 and 4).
	got, _ = st.Query(ctx, Filter{Since: base.Add(3 * time.Minute)})
	if len(got) != 2 {
		t.Fatalf("since filter: want 2, got %d", len(got))
	}

	// Limit.
	got, _ = st.Query(ctx, Filter{Limit: 1})
	if len(got) != 1 {
		t.Fatalf("limit filter: want 1, got %d", len(got))
	}
	if string(got[0].Data) != `{"n":4}` {
		t.Fatalf("limit should return newest, got %s", got[0].Data)
	}
}

func TestBoltSources(t *testing.T) {
	st := newTestBolt(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

	_ = st.Put(ctx, []Record{
		rec("nodeA", "syscall", base.Add(1*time.Minute), `{}`),
		rec("nodeA", "alert", base.Add(5*time.Minute), `{}`),
		rec("nodeB", "log", base.Add(2*time.Minute), `{}`),
	})

	stats, err := st.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	byName := map[string]SourceStat{}
	for _, s := range stats {
		byName[s.Source] = s
	}
	if byName["nodeA"].Count != 2 {
		t.Fatalf("nodeA count: want 2, got %d", byName["nodeA"].Count)
	}
	if byName["nodeB"].Count != 1 {
		t.Fatalf("nodeB count: want 1, got %d", byName["nodeB"].Count)
	}
	if !byName["nodeA"].LastSeen.Equal(base.Add(5 * time.Minute)) {
		t.Fatalf("nodeA lastSeen: want %v, got %v", base.Add(5*time.Minute), byName["nodeA"].LastSeen)
	}
}

func TestBoltPrune(t *testing.T) {
	st := newTestBolt(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

	_ = st.Put(ctx, []Record{
		rec("nodeA", "syscall", base.Add(1*time.Minute), `{}`),
		rec("nodeA", "syscall", base.Add(2*time.Minute), `{}`),
		rec("nodeB", "log", base.Add(10*time.Minute), `{}`),
	})

	// Prune everything strictly before base+5m => removes the two old nodeA recs.
	n, err := st.Prune(ctx, base.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("prune deleted: want 2, got %d", n)
	}

	got, _ := st.Query(ctx, Filter{})
	if len(got) != 1 {
		t.Fatalf("after prune: want 1 record, got %d", len(got))
	}
	if got[0].Source != "nodeB" {
		t.Fatalf("after prune: want nodeB, got %q", got[0].Source)
	}

	stats, _ := st.Sources(ctx)
	for _, s := range stats {
		if s.Source == "nodeA" {
			t.Fatalf("nodeA should be gone from sources after prune, got count %d", s.Count)
		}
	}
}

func TestBoltEmptyPut(t *testing.T) {
	st := newTestBolt(t)
	if err := st.Put(context.Background(), nil); err != nil {
		t.Fatalf("empty Put: %v", err)
	}
}

// TestPgStore exercises the Postgres backend when a DSN is provided.
func TestPgStore(t *testing.T) {
	dsn := os.Getenv("AGENTKNOX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set AGENTKNOX_TEST_PG_DSN to run the Postgres store test")
	}
	ctx := context.Background()
	st, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	base := time.Now().UTC().Truncate(time.Millisecond)
	recs := []Record{
		rec("pgNodeA", "syscall", base.Add(1*time.Minute), `{"n":1}`),
		rec("pgNodeA", "alert", base.Add(2*time.Minute), `{"n":2}`),
		rec("pgNodeB", "log", base.Add(3*time.Minute), `{"n":3}`),
	}
	if err := st.Put(ctx, recs); err != nil {
		t.Fatalf("Put: %v", err)
	}
	defer func() { _, _ = st.Prune(ctx, base.Add(24*time.Hour)) }() // cleanup

	got, err := st.Query(ctx, Filter{Source: "pgNodeA"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("pg query: want 2, got %d", len(got))
	}
	if got[0].Time.Before(got[1].Time) {
		t.Fatalf("pg query not newest-first")
	}
}
