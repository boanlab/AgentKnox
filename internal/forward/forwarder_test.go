// SPDX-License-Identifier: Apache-2.0
package forward

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/boanlab/agentknox/internal/export"
	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

// fakeAggregator captures the first Ingest call.
type fakeAggregator struct {
	pb.UnimplementedAgentKnoxAggregatorServer
	mu     sync.Mutex
	source string
	events int
	done   chan struct{}
}

func (f *fakeAggregator) Ingest(_ context.Context, req *pb.IngestRequest) (*pb.IngestResponse, error) {
	f.mu.Lock()
	f.source = req.GetSource()
	f.events = len(req.GetEvents())
	f.mu.Unlock()
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return &pb.IngestResponse{Accepted: uint32(len(req.GetEvents()))}, nil
}

func TestForwarderSendsBatch(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fake := &fakeAggregator{done: make(chan struct{})}
	gsrv := grpc.NewServer()
	pb.RegisterAgentKnoxAggregatorServer(gsrv, fake)
	go func() { _ = gsrv.Serve(lis) }()
	defer gsrv.Stop()

	f := New("node-1", lis.Addr().String(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Start(ctx)

	f.Send(export.Envelope{Kind: export.KindAlert, Time: time.Now(), Data: map[string]any{"x": 1}})
	f.Send(export.Envelope{Kind: export.KindSyscall, Time: time.Now(), Data: map[string]any{"y": 2}})

	select {
	case <-fake.done:
	case <-time.After(5 * time.Second):
		t.Fatal("aggregator never received a batch")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.source != "node-1" {
		t.Errorf("source = %q, want node-1", fake.source)
	}
	if fake.events == 0 {
		t.Fatal("no envelopes received")
	}
}

func TestForwarderDisabledWhenNoTarget(t *testing.T) {
	f := New("node-1", "", nil)
	// Must not panic or block; events are dropped when no target is set.
	f.Send(export.Envelope{Kind: export.KindAlert, Time: time.Now()})
}
