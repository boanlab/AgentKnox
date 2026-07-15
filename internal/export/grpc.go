// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"

	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

// toProto encodes an internal Envelope as a wire Envelope (data as JSON bytes).
func toProto(env Envelope) (*pb.Envelope, error) {
	data, err := json.Marshal(env.Data)
	if err != nil {
		return nil, err
	}
	return &pb.Envelope{
		Kind:         env.Kind,
		TimeUnixNano: env.Time.UnixNano(),
		Data:         data,
	}, nil
}

// Stream delivers live envelopes filtered by kind (empty = all).
func (s *Server) Stream(req *pb.StreamRequest, srv pb.AgentKnoxExport_StreamServer) error {
	kinds := map[string]bool{}
	for _, k := range req.GetKinds() {
		if k != "" {
			kinds[k] = true
		}
	}
	id, sub := s.subscribe(kinds)
	defer s.unsubscribe(id)

	ctx := srv.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env, ok := <-sub.ch:
			if !ok {
				return nil // server shutting down
			}
			msg, err := toProto(env)
			if err != nil {
				s.log.Warn("export: marshal stream envelope", zap.Error(err))
				continue
			}
			if err := srv.Send(msg); err != nil {
				return err
			}
		}
	}
}

// Recent returns the bounded replay ring for a kind (default alert).
func (s *Server) Recent(_ context.Context, req *pb.RecentRequest) (*pb.RecentResponse, error) {
	kind := req.GetKind()
	if kind == "" {
		kind = KindAlert
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultRecentLimit
	}
	envs := s.recentEnvelopes(kind, limit)
	out := &pb.RecentResponse{Events: make([]*pb.Envelope, 0, len(envs))}
	for _, env := range envs {
		msg, err := toProto(env)
		if err != nil {
			continue
		}
		out.Events = append(out.Events, msg)
	}
	return out, nil
}

// ListSessions returns a snapshot of tracked sessions as JSON blobs.
func (s *Server) ListSessions(_ context.Context, _ *pb.SessionsRequest) (*pb.SessionsResponse, error) {
	sessions := s.Sessions()
	out := &pb.SessionsResponse{Sessions: make([][]byte, 0, len(sessions))}
	for _, sess := range sessions {
		b, err := json.Marshal(sess)
		if err != nil {
			continue
		}
		out.Sessions = append(out.Sessions, b)
	}
	return out, nil
}

// ListPolicies returns the loaded-policy summary as a JSON array (empty if no
// provider is wired).
func (s *Server) ListPolicies(_ context.Context, _ *pb.PoliciesRequest) (*pb.PoliciesResponse, error) {
	var summaries any = []any{}
	if s.policyProvider != nil {
		summaries = s.policyProvider()
	}
	b, err := json.Marshal(summaries)
	if err != nil {
		return nil, err
	}
	return &pb.PoliciesResponse{Summaries: b}, nil
}
