// SPDX-License-Identifier: Apache-2.0

// Command akctl is the AgentKnox control CLI: a gRPC client for the daemon's
// AgentKnoxExport service (internal/export).
//
// Usage:
//
//	akctl [--addr host:port] <command> [flags]
//
// Commands:
//
//	sessions            List active/past AgentSessions (table).
//	stream [--kinds ..] Live-tail exported envelopes as NDJSON.
//	alerts              Print recent alerts.
//	events [--kind k]   Query the recent replay ring by kind.
//	policy              List currently loaded policy rules.
//	health              Probe the daemon's gRPC health service.
//	diagnose            Probe daemon health and report capabilities.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	pb "github.com/boanlab/agentknox/protobuf/agentknoxpb"
)

const defaultAddr = "127.0.0.1:36920"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "akctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// A global --addr flag may precede the subcommand.
	addr := defaultAddr
	rest := args
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		switch {
		case rest[0] == "--addr" || rest[0] == "-addr":
			if len(rest) < 2 {
				return fmt.Errorf("--addr requires a value")
			}
			addr, rest = rest[1], rest[2:]
		case strings.HasPrefix(rest[0], "--addr="):
			addr, rest = strings.TrimPrefix(rest[0], "--addr="), rest[1:]
		case rest[0] == "-h" || rest[0] == "--help":
			usage()
			return nil
		default:
			goto dispatch
		}
	}
dispatch:
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	cmd, cmdArgs := rest[0], rest[1:]
	c := &client{addr: addr}

	switch cmd {
	case "sessions":
		return c.sessions()
	case "stream":
		return c.stream(cmdArgs)
	case "alerts":
		return c.alerts()
	case "events":
		return c.events(cmdArgs)
	case "policy":
		return c.policy()
	case "health":
		return c.health()
	case "diagnose":
		return c.diagnose()
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `akctl — AgentKnox control CLI

Usage:
  akctl [--addr host:port] <command> [flags]

Commands:
  sessions              List active/past AgentSessions
  stream [--kinds k]    Live-tail exported envelopes as NDJSON
  alerts                Print recent alerts
  events [--kind k]     Query recent events by kind (--limit n)
  policy                List currently loaded policy rules
  health                Probe the daemon's gRPC health service
  diagnose              Probe daemon health and capabilities

Default --addr: `+defaultAddr+"\n")
}

type client struct {
	addr string
}

// dial opens a gRPC connection to the daemon.
func (c *client) dial() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.addr, err)
	}
	return conn, nil
}

func (c *client) export() (pb.AgentKnoxExportClient, *grpc.ClientConn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, nil, err
	}
	return pb.NewAgentKnoxExportClient(conn), conn, nil
}

// sessionView mirrors the pkg/types.AgentSession fields we render.
type sessionView struct {
	ID       string `json:"id"`
	Agent    string `json:"agent"`
	RootPID  int32  `json:"root_pid"`
	Coverage string `json:"coverage"`
	State    string `json:"state"`
}

func (c *client) sessions() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cl, conn, err := c.export()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := cl.ListSessions(ctx, &pb.SessionsRequest{})
	if err != nil {
		return grpcErr("sessions", c.addr, err)
	}
	if len(resp.GetSessions()) == 0 {
		fmt.Println("no sessions")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAGENT\tPID\tCOVERAGE\tSTATE")
	for _, raw := range resp.GetSessions() {
		var s sessionView
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", s.ID, s.Agent, s.RootPID, s.Coverage, s.State)
	}
	return tw.Flush()
}

func (c *client) alerts() error {
	return c.recent("alert", 100)
}

func (c *client) events(args []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	kind := fs.String("kind", "alert", "envelope kind: syscall|semantic|action|alert|edge")
	limit := fs.Int("limit", 100, "max events to return")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return c.recent(*kind, *limit)
}

func (c *client) recent(kind string, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cl, conn, err := c.export()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := cl.Recent(ctx, &pb.RecentRequest{Kind: kind, Limit: uint32(limit)})
	if err != nil {
		return grpcErr("recent", c.addr, err)
	}
	if len(resp.GetEvents()) == 0 {
		fmt.Printf("no %s events\n", kind)
		return nil
	}
	for _, env := range resp.GetEvents() {
		fmt.Println(compact(env.GetData()))
	}
	return nil
}

func (c *client) policy() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cl, conn, err := c.export()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := cl.ListPolicies(ctx, &pb.PoliciesRequest{})
	if err != nil {
		return grpcErr("policy", c.addr, err)
	}
	var rules []struct {
		Name      string   `json:"name"`
		Selector  []string `json:"selector"`
		Effect    string   `json:"effect"`
		Semantic  bool     `json:"semantic"`
		System    bool     `json:"system"`
		Condition bool     `json:"condition"`
	}
	if err := json.Unmarshal(resp.GetSummaries(), &rules); err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("no policies loaded")
		return nil
	}
	fmt.Printf("%-32s %-16s %-7s %s\n", "RULE", "SELECTOR", "EFFECT", "LAYERS")
	for _, r := range rules {
		var layers []string
		if r.Semantic {
			layers = append(layers, "semantic")
		}
		if r.System {
			layers = append(layers, "system")
		}
		if r.Condition {
			layers = append(layers, "condition")
		}
		fmt.Printf("%-32s %-16s %-7s %s\n", r.Name, strings.Join(r.Selector, ","), r.Effect, strings.Join(layers, "+"))
	}
	return nil
}

func (c *client) health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		fmt.Printf("health     UNREACHABLE (%v)\n", err)
		return nil
	}
	fmt.Printf("health     %s\n", resp.GetStatus())
	return nil
}

func (c *client) stream(args []string) error {
	fs := flag.NewFlagSet("stream", flag.ContinueOnError)
	kinds := fs.String("kinds", "", "comma-separated kinds to filter (e.g. alert,action)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	var kindList []string
	if *kinds != "" {
		kindList = strings.Split(*kinds, ",")
	}
	sc, err := pb.NewAgentKnoxExportClient(conn).Stream(ctx, &pb.StreamRequest{Kinds: kindList})
	if err != nil {
		return grpcErr("stream", c.addr, err)
	}
	for {
		env, err := sc.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil // interrupted
			}
			return err
		}
		fmt.Println(compact(env.GetData())) // NDJSON: one envelope payload per line
	}
}

func (c *client) diagnose() error {
	fmt.Printf("daemon: %s\n", c.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		fmt.Println("health: UNREACHABLE")
		fmt.Printf("  %v\n", err)
		fmt.Println("  hint: is the agentknox daemon running and is --addr correct?")
		return nil // best-effort
	}
	if resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
		fmt.Println("health: OK")
	} else {
		fmt.Printf("health: %s\n", resp.GetStatus())
	}
	fmt.Println("capabilities (gRPC AgentKnoxExport):")
	fmt.Println("  - ListSessions (akctl sessions)")
	fmt.Println("  - Stream       (akctl stream)")
	fmt.Println("  - Recent       (akctl alerts / events)")
	fmt.Println("  - ListPolicies (akctl policy)")
	return nil
}

// --- helpers ---------------------------------------------------------------

func grpcErr(op, addr string, err error) error {
	return fmt.Errorf("%s: %w (is the daemon running at %s?)", op, err, addr)
}

func compact(m json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, m); err != nil {
		return string(m)
	}
	return buf.String()
}
