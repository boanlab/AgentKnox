// SPDX-License-Identifier: Apache-2.0

// Package export implements the Exporter / WAL / gRPC serving surface.
//
// It fans the unified event, alert, action, and edge streams out to three
// sinks: an append-only JSONL WAL for a durable audit trail, live gRPC stream
// subscribers, and an in-memory recent-ring for akctl replay. It also keeps the
// latest AgentSession snapshots for `akctl sessions`.
//
// Transport is gRPC (protobuf/agentknoxpb, AgentKnoxExport service). Event
// payloads travel as JSON-encoded pkg/types values inside an Envelope, so the
// wire contract stays faithful to the canonical Go types.
package export

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/boanlab/agentknox/pkg/types"
	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

// Envelope is the internal wrapper for every exported item. One Envelope is one
// JSONL line in the WAL and one gRPC Envelope message on the stream.
type Envelope struct {
	Kind string    `json:"kind"` // syscall|semantic|action|alert|edge
	Time time.Time `json:"time"`
	Data any       `json:"data"`
}

// Sink is an additional consumer of every fanned-out envelope (e.g. the
// aggregator forwarder). Send must be non-blocking (buffer/drop internally).
type Sink interface {
	Send(env Envelope)
}

// Envelope kinds.
const (
	KindSyscall  = "syscall"
	KindSemantic = "semantic"
	KindAction   = "action"
	KindAlert    = "alert"
	KindEdge     = "edge"
)

// allKinds is the set of kinds that flow through the recent-ring, in a stable
// order for iteration.
var allKinds = []string{KindSyscall, KindSemantic, KindAction, KindAlert, KindEdge}

const (
	// queueCap bounds the ingest queue; emits are dropped when full.
	queueCap = 8192
	// ringCap is the number of recent envelopes retained per kind for replay.
	ringCap = 1024
	// subscriberCap bounds each live subscriber's buffer; slow subscribers drop.
	subscriberCap = 512
	// defaultRecentLimit is the Recent limit applied when the request asks for 0.
	defaultRecentLimit = 100
)

// Server is the concrete exporter: queue → fan-out → {WAL, gRPC subs, ring}.
type Server struct {
	pb.UnimplementedAgentKnoxExportServer

	addr string
	log  *zap.Logger

	queue    chan Envelope
	walQueue chan Envelope // WAL runs on its own goroutine (marshal is expensive)
	walDone  chan struct{}
	wal      *wal

	mu sync.RWMutex
	// rings holds the most recent envelopes per kind (bounded ring buffer).
	rings map[string]*ring
	// sessions is the latest snapshot per session ID.
	sessions map[string]*types.AgentSession
	// subs are live gRPC stream subscribers keyed by an incrementing id.
	subs   map[uint64]*subscriber
	nextID uint64
	// sinks receive every fanned-out envelope (e.g. the aggregator forwarder).
	sinks []Sink

	grpcSrv   *grpc.Server
	health    *health.Server
	closeOnce sync.Once
	loopDone  chan struct{}

	// policyProvider, if set, supplies the loaded-policy summary for ListPolicies.
	policyProvider func() any
}

// SetPolicyProvider wires a supplier of the loaded-policy summary (for
// ListPolicies and `akctl policy`).
func (s *Server) SetPolicyProvider(fn func() any) { s.policyProvider = fn }

// subscriber is one live gRPC stream consumer with an optional kind filter.
type subscriber struct {
	ch    chan Envelope
	kinds map[string]bool // nil/empty means all kinds
}

// New constructs a Server. It creates walDir and prepares (but does not start)
// the gRPC server. Call Start to serve on addr.
func New(addr, walDir string, log *zap.Logger) (*Server, error) {
	if log == nil {
		log = zap.NewNop()
	}
	w, err := newWAL(walDir, log)
	if err != nil {
		return nil, err
	}
	s := &Server{
		addr:     addr,
		log:      log,
		queue:    make(chan Envelope, queueCap),
		walQueue: make(chan Envelope, queueCap),
		walDone:  make(chan struct{}),
		wal:      w,
		rings:    make(map[string]*ring, len(allKinds)),
		sessions: make(map[string]*types.AgentSession),
		subs:     make(map[uint64]*subscriber),
		loopDone: make(chan struct{}),
	}
	for _, k := range allKinds {
		s.rings[k] = newRing(ringCap)
	}
	return s, nil
}

// --- pipeline.Exporter -----------------------------------------------------

// EmitSyscall enqueues a system-layer event.
func (s *Server) EmitSyscall(ev *types.SyscallEvent) {
	if ev == nil {
		return
	}
	s.enqueue(Envelope{Kind: KindSyscall, Time: ev.Time, Data: ev})
}

// EmitSemantic enqueues a semantic-layer event.
func (s *Server) EmitSemantic(ev *types.SemanticEvent) {
	if ev == nil {
		return
	}
	s.enqueue(Envelope{Kind: KindSemantic, Time: ev.Time, Data: ev})
}

// EmitAction enqueues a correlated action (intent → effects).
func (s *Server) EmitAction(a *types.CorrelatedAction) {
	if a == nil {
		return
	}
	s.enqueue(Envelope{Kind: KindAction, Time: a.Time, Data: a})
}

// EmitAlert enqueues an alert.
func (s *Server) EmitAlert(al *types.Alert) {
	if al == nil {
		return
	}
	s.enqueue(Envelope{Kind: KindAlert, Time: al.Time, Data: al})
}

// EmitEdge enqueues a provenance graph edge.
func (s *Server) EmitEdge(e *types.GraphEdge) {
	if e == nil {
		return
	}
	s.enqueue(Envelope{Kind: KindEdge, Time: e.Time, Data: e})
}

// enqueue performs a non-blocking send onto the ingest queue; on backpressure
// the envelope is dropped.
func (s *Server) enqueue(env Envelope) {
	if env.Time.IsZero() {
		env.Time = time.Now()
	}
	select {
	case s.queue <- env:
	default:
	}
}

// --- session snapshots -----------------------------------------------------

// UpdateSession records the latest snapshot of a session for ListSessions. The
// pipeline calls this as sessions are created, enriched, or ended.
func (s *Server) UpdateSession(sess *types.AgentSession) {
	if sess == nil {
		return
	}
	cp := *sess // shallow copy: decouple from the manager's live struct
	s.mu.Lock()
	s.sessions[cp.ID] = &cp
	s.mu.Unlock()
}

// Sessions returns a snapshot list of tracked sessions.
func (s *Server) Sessions() []*types.AgentSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*types.AgentSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

// recentEnvelopes returns up to limit most-recent envelopes for a kind.
func (s *Server) recentEnvelopes(kind string, limit int) []Envelope {
	s.mu.RLock()
	r := s.rings[kind]
	s.mu.RUnlock()
	if r == nil {
		return nil
	}
	return r.snapshot(limit)
}

// --- subscriber management -------------------------------------------------

// subscribe registers a live subscriber for the given kinds (empty = all).
func (s *Server) subscribe(kinds map[string]bool) (uint64, *subscriber) {
	sub := &subscriber{ch: make(chan Envelope, subscriberCap), kinds: kinds}
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = sub
	s.mu.Unlock()
	return id, sub
}

func (s *Server) unsubscribe(id uint64) {
	s.mu.Lock()
	if sub, ok := s.subs[id]; ok {
		close(sub.ch)
		delete(s.subs, id)
	}
	s.mu.Unlock()
}

// --- lifecycle -------------------------------------------------------------

// Start launches the gRPC server and the fan-out loop, then blocks until ctx is
// cancelled, at which point it shuts everything down. Meant to run in its own
// goroutine.
func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.grpcSrv = grpc.NewServer()
	pb.RegisterAgentKnoxExportServer(s.grpcSrv, s)
	s.health = health.NewServer()
	healthpb.RegisterHealthServer(s.grpcSrv, s.health)

	go s.walLoop()
	go s.fanout()

	s.health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	s.log.Info("export: gRPC serving", zap.String("addr", s.addr))

	go func() {
		if serr := s.grpcSrv.Serve(lis); serr != nil {
			s.log.Error("export: gRPC server exited", zap.Error(serr))
		}
	}()

	<-ctx.Done()
	return s.Close()
}

// walLoop marshals+appends to the WAL on its own goroutine, so the reflection-
// heavy json.Marshal (the single most expensive per-event step) does not gate
// the fanout loop's throughput. Order is preserved by the FIFO channel.
func (s *Server) walLoop() {
	defer close(s.walDone)
	for env := range s.walQueue {
		if err := s.wal.append(env); err != nil {
			s.log.Warn("export: wal append", zap.Error(err))
		}
	}
}

// fanout drains the ingest queue: ring update, broadcast, sinks. The WAL append
// is handed to walLoop so this loop stays fast.
func (s *Server) fanout() {
	defer close(s.loopDone)
	for env := range s.queue {
		select {
		case s.walQueue <- env:
		default: // WAL backpressure: drop the audit copy, keep serving
		}
		s.mu.Lock()
		if r := s.rings[env.Kind]; r != nil {
			r.push(env)
		}
		s.broadcastLocked(env)
		s.mu.Unlock()

		for _, sink := range s.sinks {
			sink.Send(env)
		}
	}
}

// AddSink registers an additional envelope consumer (e.g. the aggregator
// forwarder). Call before Start.
func (s *Server) AddSink(sink Sink) {
	if sink != nil {
		s.sinks = append(s.sinks, sink)
	}
}

// broadcastLocked delivers env to matching live subscribers, non-blocking.
// Caller holds s.mu.
func (s *Server) broadcastLocked(env Envelope) {
	for _, sub := range s.subs {
		if len(sub.kinds) > 0 && !sub.kinds[env.Kind] {
			continue
		}
		select {
		case sub.ch <- env:
		default:
		}
	}
}

// Close flushes the WAL and stops the server. Safe to call multiple times.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.health != nil {
			s.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		}
		if s.grpcSrv != nil {
			s.grpcSrv.GracefulStop()
		}

		// Stop the fan-out loop and drain, then drain the WAL loop, then close.
		close(s.queue)
		<-s.loopDone
		close(s.walQueue)
		<-s.walDone
		if ferr := s.wal.close(); ferr != nil {
			err = ferr
		}

		// Close live subscriber channels so open stream handlers unwind.
		s.mu.Lock()
		for id, sub := range s.subs {
			close(sub.ch)
			delete(s.subs, id)
		}
		s.mu.Unlock()
	})
	return err
}
