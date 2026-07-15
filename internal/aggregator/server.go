// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"context"
	"net"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

// retentionInterval is how often the background prune loop runs.
const retentionInterval = time.Hour

// Config configures the aggregator Server.
type Config struct {
	ListenAddr string        // gRPC listen address, e.g. ":36930"
	Retention  time.Duration // 0 disables background pruning
}

// Server is the central aggregator: it ingests envelopes from daemons into a
// Store and serves a gRPC query API (AgentKnoxAggregator service).
type Server struct {
	pb.UnimplementedAgentKnoxAggregatorServer

	store Store
	cfg   Config
	log   *zap.Logger

	grpcSrv *grpc.Server
	health  *health.Server
}

// New constructs a Server. It does not start serving; call Start.
func New(store Store, cfg Config, log *zap.Logger) *Server {
	if log == nil {
		log = zap.NewNop()
	}
	return &Server{store: store, cfg: cfg, log: log}
}

// Start launches the gRPC server and the retention loop, then blocks until ctx
// is cancelled, at which point it shuts everything down.
func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.grpcSrv = grpc.NewServer()
	pb.RegisterAgentKnoxAggregatorServer(s.grpcSrv, s)
	s.health = health.NewServer()
	healthpb.RegisterHealthServer(s.grpcSrv, s.health)
	s.health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	go s.retentionLoop(ctx)
	s.log.Info("aggregator: gRPC serving", zap.String("addr", s.cfg.ListenAddr))

	go func() {
		if serr := s.grpcSrv.Serve(lis); serr != nil {
			s.log.Error("aggregator: gRPC server exited", zap.Error(serr))
		}
	}()

	<-ctx.Done()
	return s.Close()
}

// Close stops the gRPC server and closes the store. Safe to call once.
func (s *Server) Close() error {
	if s.health != nil {
		s.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
	return s.store.Close()
}

// --- RPCs ------------------------------------------------------------------

// Ingest stores a batch of envelopes forwarded by a daemon.
func (s *Server) Ingest(ctx context.Context, req *pb.IngestRequest) (*pb.IngestResponse, error) {
	source := req.GetSource()
	if source == "" {
		return &pb.IngestResponse{}, status.Error(codes.InvalidArgument, "missing source")
	}
	recs := make([]Record, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		t := time.Unix(0, e.GetTimeUnixNano())
		if e.GetTimeUnixNano() == 0 {
			t = time.Now()
		}
		recs = append(recs, Record{Source: source, Kind: e.GetKind(), Time: t, Data: e.GetData()})
	}
	if err := s.store.Put(ctx, recs); err != nil {
		s.log.Warn("aggregator: store put", zap.String("source", source), zap.Error(err))
		return &pb.IngestResponse{}, status.Error(codes.Internal, "store error")
	}
	return &pb.IngestResponse{Accepted: uint32(len(recs))}, nil
}

// Query returns stored records matching the filter, newest-first.
func (s *Server) Query(ctx context.Context, req *pb.QueryRequest) (*pb.QueryResponse, error) {
	f := Filter{
		Source: req.GetSource(),
		Kind:   req.GetKind(),
		Limit:  int(req.GetLimit()),
	}
	if ns := req.GetSinceUnixNano(); ns > 0 {
		f.Since = time.Unix(0, ns)
	}
	recs, err := s.store.Query(ctx, f)
	if err != nil {
		return nil, status.Error(codes.Internal, "query error")
	}
	out := &pb.QueryResponse{Records: make([]*pb.Record, 0, len(recs))}
	for _, r := range recs {
		out.Records = append(out.Records, &pb.Record{
			Source:       r.Source,
			Kind:         r.Kind,
			TimeUnixNano: r.Time.UnixNano(),
			Data:         r.Data,
		})
	}
	return out, nil
}

// Sources reports per-source ingest statistics.
func (s *Server) Sources(ctx context.Context, _ *pb.SourcesRequest) (*pb.SourcesResponse, error) {
	stats, err := s.store.Sources(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "sources error")
	}
	out := &pb.SourcesResponse{Sources: make([]*pb.SourceStat, 0, len(stats))}
	for _, st := range stats {
		out.Sources = append(out.Sources, &pb.SourceStat{
			Source:           st.Source,
			Count:            st.Count,
			LastSeenUnixNano: st.LastSeen.UnixNano(),
		})
	}
	return out, nil
}

// --- background ------------------------------------------------------------

// retentionLoop periodically prunes records older than the retention window.
func (s *Server) retentionLoop(ctx context.Context) {
	if s.cfg.Retention <= 0 {
		return
	}
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-s.cfg.Retention)
			n, err := s.store.Prune(ctx, cutoff)
			if err != nil {
				s.log.Warn("aggregator: prune", zap.Error(err))
				continue
			}
			if n > 0 {
				s.log.Info("aggregator: pruned old records", zap.Int64("deleted", n), zap.Time("cutoff", cutoff))
			}
		}
	}
}
