// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, Config{}, nil)
}

func TestIngestThenQuery(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	when := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)

	_, err := srv.Ingest(ctx, &pb.IngestRequest{
		Source: "node-1",
		Events: []*pb.Envelope{
			{Kind: "syscall", TimeUnixNano: when.UnixNano(), Data: json.RawMessage(`{"pid":42}`)},
			{Kind: "alert", TimeUnixNano: when.Add(time.Second).UnixNano(), Data: json.RawMessage(`{"rule":"x"}`)},
		},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Query returns both, newest-first.
	q, err := srv.Query(ctx, &pb.QueryRequest{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(q.GetRecords()) != 2 {
		t.Fatalf("want 2 records, got %d", len(q.GetRecords()))
	}
	if q.GetRecords()[0].GetKind() != "alert" {
		t.Fatalf("want newest-first (alert), got %q", q.GetRecords()[0].GetKind())
	}
	if q.GetRecords()[0].GetSource() != "node-1" {
		t.Fatalf("source not tagged: %q", q.GetRecords()[0].GetSource())
	}

	// Filter by kind.
	q, err = srv.Query(ctx, &pb.QueryRequest{Kind: "syscall"})
	if err != nil {
		t.Fatalf("Query(kind): %v", err)
	}
	if len(q.GetRecords()) != 1 || q.GetRecords()[0].GetKind() != "syscall" {
		t.Fatalf("kind filter failed: %v", q.GetRecords())
	}

	// Sources.
	s, err := srv.Sources(ctx, &pb.SourcesRequest{})
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	if len(s.GetSources()) != 1 || s.GetSources()[0].GetSource() != "node-1" || s.GetSources()[0].GetCount() != 2 {
		t.Fatalf("sources unexpected: %+v", s.GetSources())
	}
}

func TestIngestMissingSource(t *testing.T) {
	srv := newTestServer(t)
	if _, err := srv.Ingest(context.Background(), &pb.IngestRequest{}); err == nil {
		t.Fatal("missing source: want error, got nil")
	}
}
