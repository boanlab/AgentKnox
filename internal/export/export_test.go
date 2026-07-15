// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/boanlab/agentknox/pkg/types"
	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

// startTestServer boots a Server on an ephemeral port with a temp WAL dir and
// returns it plus an export gRPC client. It waits until the health check passes.
func startTestServer(t *testing.T) (*Server, pb.AgentKnoxExportClient) {
	t.Helper()
	addr := freeAddr(t)
	s, err := New(addr, t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitHealthy(t, conn)
	return s, pb.NewAgentKnoxExportClient(conn)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitHealthy(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	hc := healthpb.NewHealthClient(conn)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		cancel()
		if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never became healthy")
}

func TestEmitAndRecent(t *testing.T) {
	s, cl := startTestServer(t)

	s.EmitAlert(&types.Alert{
		AlertID:  "a1",
		Time:     time.Now(),
		Severity: "critical",
		Effect:   types.EffectBlock,
		Reason:   "test alert",
	})
	s.EmitSyscall(&types.SyscallEvent{EventID: "e1", Time: time.Now(), Name: "connect"})
	s.EmitAction(&types.CorrelatedAction{ActionID: "act1", Time: time.Now(), ToolName: "bash"})

	// Poll Recent until the alert lands (fan-out is async).
	var alerts []*pb.Envelope
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := cl.Recent(context.Background(), &pb.RecentRequest{Kind: "alert"})
		if err != nil {
			t.Fatalf("Recent: %v", err)
		}
		alerts = resp.GetEvents()
		if len(alerts) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(alerts) != 1 {
		t.Fatalf("recent alerts = %d, want 1", len(alerts))
	}
	if alerts[0].GetKind() != KindAlert {
		t.Fatalf("kind = %q, want alert", alerts[0].GetKind())
	}

	resp, err := cl.Recent(context.Background(), &pb.RecentRequest{Kind: "syscall"})
	if err != nil {
		t.Fatalf("Recent(syscall): %v", err)
	}
	if len(resp.GetEvents()) != 1 {
		t.Fatalf("recent syscalls = %d, want 1", len(resp.GetEvents()))
	}
}

func TestWALWritten(t *testing.T) {
	walDir := t.TempDir()
	s, err := New(freeAddr(t), walDir, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Start(ctx) }()

	for i := 0; i < 5; i++ {
		s.EmitAlert(&types.Alert{AlertID: "a", Time: time.Now(), Effect: types.EffectAlert, Reason: "x"})
	}
	// Allow fan-out to drain, then close to flush the WAL.
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if len(matches) == 0 {
		t.Fatal("no WAL segment written")
	}
	f, err := os.Open(matches[0])
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer f.Close()
	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var env Envelope
		if err := json.Unmarshal(sc.Bytes(), &env); err != nil {
			t.Fatalf("wal line not valid JSON: %v", err)
		}
		if env.Kind != KindAlert {
			t.Fatalf("wal envelope kind = %q, want alert", env.Kind)
		}
		lines++
	}
	if lines != 5 {
		t.Fatalf("wal lines = %d, want 5", lines)
	}
}

func TestListSessions(t *testing.T) {
	s, cl := startTestServer(t)
	s.UpdateSession(&types.AgentSession{
		ID:       "s1",
		Agent:    types.AgentClaudeCode,
		RootPID:  1234,
		Coverage: types.CoverageFull,
		State:    types.SessionActive,
	})

	resp, err := cl.ListSessions(context.Background(), &pb.SessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(resp.GetSessions()))
	}
	var sess types.AgentSession
	if err := json.Unmarshal(resp.GetSessions()[0], &sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sess.ID != "s1" {
		t.Fatalf("session id = %q, want s1", sess.ID)
	}
}

func TestStream(t *testing.T) {
	s, cl := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sc, err := cl.Stream(ctx, &pb.StreamRequest{Kinds: []string{"alert"}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Emit after subscribing.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.EmitAlert(&types.Alert{AlertID: "live", Time: time.Now(), Effect: types.EffectKill, Reason: "live"})
	}()

	env, err := sc.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if env.GetKind() != KindAlert {
		t.Fatalf("kind = %q, want alert", env.GetKind())
	}
	if want := "\"live\""; !bytesContains(env.GetData(), want) {
		t.Fatalf("payload %q missing %q", env.GetData(), want)
	}
}

func bytesContains(b []byte, sub string) bool {
	return len(b) > 0 && json.Valid(b) && contains(string(b), sub)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
