// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/sensor"
)

// mcpMaxChunksBeforeEvict bounds how much traffic a candidate pipe may produce
// without yielding a JSON-RPC message before it is written off as non-MCP and
// unregistered (behavioral confirmation).
const mcpMaxChunksBeforeEvict = 32

// mcpDetector identifies stdio-transport MCP servers among a session's processes
// and registers their stdin/stdout pipe fds for capture. A local MCP server
// exchanges JSON-RPC over pipes (fd 0 read = request, fd 1 write = response),
// which never crosses the TLS boundary the uprobes watch. Candidates are chosen
// behaviorally — a session child whose stdin AND stdout are both pipes — and
// confirmed by observing JSON-RPC on the captured stream; a candidate that never
// produces JSON-RPC is evicted so unrelated pipes are not captured.
type mcpDetector struct {
	loader *sensor.Loader
	log    *zap.Logger

	mu   sync.Mutex
	cand map[int32]*mcpCand
}

type mcpCand struct {
	chunks int
	mcp    bool
}

func newMCPDetector(l *sensor.Loader, log *zap.Logger) *mcpDetector {
	return &mcpDetector{loader: l, log: log, cand: make(map[int32]*mcpCand)}
}

// consider registers a session member for stdio-MCP capture if both its stdin
// and stdout are pipes. Idempotent.
func (m *mcpDetector) consider(pid int32) {
	if m == nil || m.loader == nil || pid <= 1 {
		return
	}
	if !isFifo(pid, 0) || !isFifo(pid, 1) {
		return
	}
	m.mu.Lock()
	if _, ok := m.cand[pid]; ok {
		m.mu.Unlock()
		return
	}
	m.cand[pid] = &mcpCand{}
	n := len(m.cand)
	m.mu.Unlock()

	_ = m.loader.RegisterMcpFd(uint32(pid), 0)
	_ = m.loader.RegisterMcpFd(uint32(pid), 1)
	if n == 1 { // 0 -> 1: arm the global write/read hooks
		_ = m.loader.SetMcpArmed(true)
	}
	m.log.Debug("stdio-mcp: registered candidate pipe fds",
		zap.Int32("pid", pid), zap.String("server", mcpServerLabel(pid)))
}

// mcpServerLabel derives a human-readable name for a candidate MCP server from
// its command line (an arg mentioning mcp/server, else argv[0]'s basename).
func mcpServerLabel(pid int32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	for _, a := range parts {
		la := strings.ToLower(a)
		if strings.Contains(la, "mcp") || strings.Contains(la, "server") {
			return filepath.Base(a)
		}
	}
	if len(parts) > 0 {
		return filepath.Base(parts[0])
	}
	return ""
}

// noteChunk records a captured semantic chunk for a candidate pid and either
// confirms it (JSON-RPC seen) or evicts it once it has produced too much
// non-JSON-RPC traffic.
func (m *mcpDetector) noteChunk(pid int32, isMCP bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	c := m.cand[pid]
	if c == nil {
		m.mu.Unlock()
		return
	}
	c.chunks++
	if isMCP {
		c.mcp = true
	}
	evict := !c.mcp && c.chunks >= mcpMaxChunksBeforeEvict
	n := len(m.cand)
	if evict {
		delete(m.cand, pid)
		n = len(m.cand)
	}
	m.mu.Unlock()

	if evict {
		_ = m.loader.UnregisterMcpFd(uint32(pid), 0)
		_ = m.loader.UnregisterMcpFd(uint32(pid), 1)
		if n == 0 { // last candidate gone: disarm
			_ = m.loader.SetMcpArmed(false)
		}
		m.log.Debug("stdio-mcp: evicted non-JSON-RPC pipe", zap.Int32("pid", pid))
	}
}

// forget unregisters a pid's captured fds (on process/session exit).
func (m *mcpDetector) forget(pid int32) {
	if m == nil {
		return
	}
	m.mu.Lock()
	_, ok := m.cand[pid]
	delete(m.cand, pid)
	n := len(m.cand)
	m.mu.Unlock()
	if ok {
		_ = m.loader.UnregisterMcpFd(uint32(pid), 0)
		_ = m.loader.UnregisterMcpFd(uint32(pid), 1)
		if n == 0 {
			_ = m.loader.SetMcpArmed(false)
		}
	}
}

// isFifo reports whether fd of pid resolves to a pipe/FIFO.
func isFifo(pid int32, fd int) bool {
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeNamedPipe != 0
}
