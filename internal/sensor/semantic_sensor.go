// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/pkg/types"
)

// SemanticSensor reads the ak_semantic ring and attaches TLS uprobes at
// resolver-supplied offsets. It implements pipeline.SemanticSensor.
//
// Uprobes attach GLOBALLY on the target binary (pid 0), not the resolved pid;
// the BPF programs gate emission on the caller's cgroup being a registered
// session (ak_sessions). Global attach is required because a launcher (e.g.
// `node <cli>`) commonly re-execs into a worker child that owns the TLS
// connections, so a pid-scoped uprobe would never fire. Attaches are
// deduplicated per binary path and reference-counted across sessions.
type SemanticSensor struct {
	loader *Loader
	log    *zap.Logger
	reader *ringbuf.Reader
	out    chan types.SemanticChunk

	mu        sync.Mutex
	byBinary  map[string]*binaryAttach // binary path -> shared global uprobe links
	pidBinary map[int32]string         // session pid -> its binary path (for Detach)
}

// binaryAttach holds the global uprobe links for one binary and the set of
// session pids that requested them; the links are closed when the last releases.
type binaryAttach struct {
	links []link.Link
	pids  map[int32]bool
}

func NewSemanticSensor(l *Loader, log *zap.Logger) *SemanticSensor {
	return &SemanticSensor{
		loader: l, log: log,
		out:       make(chan types.SemanticChunk, 8192),
		byBinary:  make(map[string]*binaryAttach),
		pidBinary: make(map[int32]string),
	}
}

func (s *SemanticSensor) Start(ctx context.Context) (<-chan types.SemanticChunk, error) {
	rd, err := ringbuf.NewReader(s.loader.SemanticMap())
	if err != nil {
		return nil, err
	}
	s.reader = rd
	go s.loop(ctx)
	return s.out, nil
}

func (s *SemanticSensor) loop(ctx context.Context) {
	defer close(s.out)
	go func() {
		<-ctx.Done()
		_ = s.reader.Close()
	}()
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		f, err := bpf2frame.Decode(rec.RawSample)
		if err != nil {
			continue
		}
		chunk := bpf2frame.MapSemantic(f)
		select {
		case s.out <- chunk:
		default:
		}
	}
}

// uprobeAt attaches an entry uprobe for prog at off, logging any attach error.
func (s *SemanticSensor) uprobeAt(ex *link.Executable, pid int32, off uint64, prog, key string, links []link.Link) []link.Link {
	p := s.loader.Program(prog)
	if p == nil {
		return links
	}
	lk, err := ex.Uprobe("", p, &link.UprobeOptions{Address: off, PID: int(pid)})
	if err != nil {
		s.log.Debug("uprobe attach failed", zap.String("key", key), zap.String("prog", prog),
			zap.Uint64("offset", off), zap.Int32("pid", pid), zap.Error(err))
		return links
	}
	return append(links, lk)
}

// uretprobeAt attaches a return uretprobe for prog at off, logging any error.
func (s *SemanticSensor) uretprobeAt(ex *link.Executable, pid int32, off uint64, prog, key string, links []link.Link) []link.Link {
	p := s.loader.Program(prog)
	if p == nil {
		return links
	}
	lk, err := ex.Uretprobe("", p, &link.UprobeOptions{Address: off, PID: int(pid)})
	if err != nil {
		s.log.Debug("uretprobe attach failed", zap.String("key", key), zap.String("prog", prog),
			zap.Uint64("offset", off), zap.Int32("pid", pid), zap.Error(err))
		return links
	}
	return append(links, lk)
}

// attachEntry attaches an entry uprobe (prog) at plan.Offsets[key] if present.
func (s *SemanticSensor) attachEntry(ex *link.Executable, pid int32, plan *types.AttachPlan, key, prog string, links []link.Link) []link.Link {
	off, ok := plan.Offsets[key]
	if !ok {
		return links
	}
	return s.uprobeAt(ex, pid, off, prog, key, links)
}

// attachEntryExit attaches an entry uprobe and a return uretprobe at the same
// offset (the return probe reads a buffer stashed at entry).
func (s *SemanticSensor) attachEntryExit(ex *link.Executable, pid int32, plan *types.AttachPlan, key, enter, exit string, links []link.Link) []link.Link {
	off, ok := plan.Offsets[key]
	if !ok {
		return links
	}
	links = s.uprobeAt(ex, pid, off, enter, key, links)
	links = s.uretprobeAt(ex, pid, off, exit, key, links)
	return links
}

// attachPlanLinks attaches every uprobe the plan calls for and returns the
// links. pid selects the target process; pid 0 attaches to all processes running
// the binary (cilium/ebpf perfAllThreads). Caller holds s.mu.
func (s *SemanticSensor) attachPlanLinks(ex *link.Executable, pid int32, plan *types.AttachPlan) []link.Link {
	var links []link.Link
	if off, ok := plan.Offsets["write"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_ssl_write", "write", links)
	}
	if off, ok := plan.Offsets["read"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_ssl_read_enter", "read", links)
		links = s.uretprobeAt(ex, pid, off, "ak_ssl_read_exit", "read", links)
	}
	// AEAD boundary (T7: rustls/aws-lc-rs). seal = outbound plaintext at entry;
	// open = inbound plaintext at return.
	if off, ok := plan.Offsets["aead_seal"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_aead_seal", "aead_seal", links)
	}
	if off, ok := plan.Offsets["aead_open"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_aead_open_enter", "aead_open", links)
		links = s.uretprobeAt(ex, pid, off, "ak_aead_open_exit", "aead_open", links)
	}
	// ASM AEAD boundary (stripped rustls/aws-lc-rs, e.g. Codex). chacha/aesni-gcm
	// decrypt output the plaintext on return; encrypt/seal input it at entry.
	links = s.attachEntry(ex, pid, plan, "chacha_seal", "ak_chacha_seal", links)
	links = s.attachEntry(ex, pid, plan, "aesni_gcm_enc", "ak_aesgcm_enc", links)
	links = s.attachEntry(ex, pid, plan, "aes_gcm_enc_avx512", "ak_aesgcm512_enc", links)
	links = s.attachEntryExit(ex, pid, plan, "chacha_open", "ak_chacha_open_enter", "ak_chacha_open_exit", links)
	links = s.attachEntryExit(ex, pid, plan, "aesni_gcm_dec", "ak_aesgcm_dec_enter", "ak_aesgcm_dec_exit", links)
	links = s.attachEntryExit(ex, pid, plan, "aes_gcm_dec_avx512", "ak_aesgcm512_dec_enter", "ak_aesgcm512_dec_exit", links)
	// Go crypto/tls boundary (pure-Go TLS, e.g. Crush). Write captures the full
	// outbound plaintext at entry; Read is captured via uprobes on the function's
	// RET instructions (Go's goroutine-stack moves make uretprobe unsafe).
	if off, ok := plan.Offsets["go_write"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_gotls_write", "go_write", links)
	}
	if off, ok := plan.Offsets["go_read"]; ok {
		links = s.uprobeAt(ex, pid, off, "ak_gotls_read_enter", "go_read", links)
		for _, ret := range plan.GoReadRets {
			links = s.uprobeAt(ex, pid, ret, "ak_gotls_read_ret", "go_read_ret", links)
		}
	}
	return links
}

// Attach installs the plan's uprobes globally on the target binary, gated in BPF
// by the caller's cgroup. The first session for a binary creates the links;
// later sessions reuse them, so a shared runtime (e.g. /usr/bin/node) is
// instrumented once for every session's worker processes.
func (s *SemanticSensor) Attach(pid int32, plan *types.AttachPlan) error {
	if plan == nil || plan.Boundary == types.BoundaryNone {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if ba, ok := s.byBinary[plan.BinaryPath]; ok {
		ba.pids[pid] = true
		s.pidBinary[pid] = plan.BinaryPath
		return nil
	}

	ex, err := link.OpenExecutable(plan.BinaryPath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", plan.BinaryPath, err)
	}
	// pid 0: attach to every process running this binary, present and future
	// (covers a worker child spawned after attach). BPF gates emission on cgroup.
	links := s.attachPlanLinks(ex, 0, plan)
	if len(links) == 0 {
		return fmt.Errorf("no uprobes attached for %s", plan.BinaryPath)
	}
	s.byBinary[plan.BinaryPath] = &binaryAttach{links: links, pids: map[int32]bool{pid: true}}
	s.pidBinary[pid] = plan.BinaryPath
	return nil
}

func (s *SemanticSensor) Detach(pid int32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, ok := s.pidBinary[pid]
	if !ok {
		return nil
	}
	delete(s.pidBinary, pid)
	ba := s.byBinary[path]
	if ba == nil {
		return nil
	}
	delete(ba.pids, pid)
	if len(ba.pids) == 0 { // last session for this binary: tear down the links
		for _, lk := range ba.links {
			_ = lk.Close()
		}
		delete(s.byBinary, path)
	}
	return nil
}

func (s *SemanticSensor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ba := range s.byBinary {
		for _, lk := range ba.links {
			_ = lk.Close()
		}
	}
	if s.reader != nil {
		return s.reader.Close()
	}
	return nil
}
