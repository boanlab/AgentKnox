// SPDX-License-Identifier: Apache-2.0
// Package forward ships event envelopes from a daemon to a central aggregator
// (multi-host deployments). It is an exporter sink: it batches envelopes and
// sends them over the AgentKnoxAggregator Ingest RPC. The target is hot-swappable
// — the daemon updates it when the config file changes, with no restart. When no
// target is set, forwarding is disabled and events stay local.
package forward

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/boanlab/agentknox/internal/export"
	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

const (
	batchMax      = 256
	flushInterval = 2 * time.Second
	bufferSize    = 8192
	dialTimeout   = 10 * time.Second
)

// Forwarder implements export.Sink. Safe for concurrent Send.
type Forwarder struct {
	source string
	log    *zap.Logger

	queue chan export.Envelope

	mu     sync.Mutex
	target string
	conn   *grpc.ClientConn
	client pb.AgentKnoxAggregatorClient
}

// New creates a Forwarder tagging events with source (the node name). initial may
// be "" (disabled until SetTarget).
func New(source, initial string, log *zap.Logger) *Forwarder {
	if log == nil {
		log = zap.NewNop()
	}
	f := &Forwarder{
		source: source,
		log:    log,
		queue:  make(chan export.Envelope, bufferSize),
	}
	f.SetTarget(initial)
	return f
}

// SetTarget updates (or clears) the aggregator gRPC address. Called on config
// reload. A changed target tears down the old connection and dials the new one.
func (f *Forwarder) SetTarget(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if addr == f.target {
		return
	}
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn, f.client = nil, nil
	}
	f.target = addr
	if addr == "" {
		f.log.Info("forward: aggregator forwarding disabled")
		return
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		f.log.Warn("forward: dial aggregator failed", zap.String("target", addr), zap.Error(err))
		return
	}
	f.conn = conn
	f.client = pb.NewAgentKnoxAggregatorClient(conn)
	f.log.Info("forward: forwarding events to aggregator", zap.String("target", addr))
}

// clientRef returns the current client (nil when forwarding is disabled).
func (f *Forwarder) clientRef() pb.AgentKnoxAggregatorClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.client
}

// Send enqueues an envelope (non-blocking). Implements export.Sink.
func (f *Forwarder) Send(env export.Envelope) {
	if f.clientRef() == nil {
		return
	}
	select {
	case f.queue <- env:
	default: // queue full: drop rather than stall the exporter
	}
}

// Start runs the batch loop until ctx is done.
func (f *Forwarder) Start(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]export.Envelope, 0, batchMax)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		f.send(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			f.closeConn()
			return
		case env := <-f.queue:
			batch = append(batch, env)
			if len(batch) >= batchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (f *Forwarder) closeConn() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn, f.client = nil, nil
	}
}

func (f *Forwarder) send(ctx context.Context, batch []export.Envelope) {
	client := f.clientRef()
	if client == nil {
		return
	}
	events := make([]*pb.Envelope, 0, len(batch))
	for _, env := range batch {
		data, err := json.Marshal(env.Data)
		if err != nil {
			continue
		}
		events = append(events, &pb.Envelope{
			Kind:         env.Kind,
			TimeUnixNano: env.Time.UnixNano(),
			Data:         data,
		})
	}
	if len(events) == 0 {
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if _, err := client.Ingest(sendCtx, &pb.IngestRequest{Source: f.source, Events: events}); err != nil {
		f.log.Warn("forward: ingest to aggregator failed", zap.Error(err))
	}
}
