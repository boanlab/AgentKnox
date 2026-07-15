// SPDX-License-Identifier: Apache-2.0

// Command resolveprobe exercises the Semantic Attach Resolver tier ladder on a
// live process, printing the resulting AttachPlan (tier, boundary, coverage,
// confidence, offsets) as JSON. A diagnostic tool for working on the resolver,
// not part of the daemon's supported surface.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/boanlab/agentknox/internal/resolver"
	"github.com/boanlab/agentknox/pkg/types"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: resolveprobe <pid> <agent:claude-code|codex|crush|gemini|unknown> [offsetDBPath]")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad pid:", err)
		os.Exit(2)
	}
	agent := types.AgentKind(os.Args[2])
	dbPath := ""
	if len(os.Args) > 3 {
		dbPath = os.Args[3]
	}
	r := resolver.New(dbPath, nil)

	start := time.Now()
	plan, err := r.Resolve(int32(pid), agent)
	elapsed := time.Since(start)

	out := map[string]any{
		"pid":           pid,
		"agent":         string(agent),
		"resolve_ms":    float64(elapsed.Microseconds()) / 1000.0,
		"tls_lib_found": func() string { l, _ := resolver.FindProcessTLSLib(int32(pid)); return l }(),
	}
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["plan"] = plan
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}
