// SPDX-License-Identifier: Apache-2.0
// Package sensor owns the eBPF objects: it loads the embedded CO-RE object,
// attaches programs, exposes the shared maps (for the enforcer), and provides
// the System and Semantic sensors.
package sensor

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed agentknox_bpfel.o
var bpfObject []byte

// Loader holds the loaded collection and attached links.
type Loader struct {
	coll  *ebpf.Collection
	links []link.Link
}

// tracepointAttach lists (program, category, name) for tracepoint programs.
var tracepointAttach = []struct {
	prog, group, name string
}{
	{"ak_execve", "syscalls", "sys_enter_execve"},
	{"ak_execveat", "syscalls", "sys_enter_execveat"},
	{"ak_proc_fork", "sched", "sched_process_fork"},
	{"ak_proc_exit", "sched", "sched_process_exit"},
	{"ak_openat", "syscalls", "sys_enter_openat"},
	{"ak_openat2", "syscalls", "sys_enter_openat2"},
	{"ak_connect", "syscalls", "sys_enter_connect"},
	{"ak_sendto", "syscalls", "sys_enter_sendto"},
	{"ak_recvfrom_enter", "syscalls", "sys_enter_recvfrom"},
	{"ak_recvfrom_exit", "syscalls", "sys_exit_recvfrom"},
	{"ak_recvmsg_enter", "syscalls", "sys_enter_recvmsg"},
	{"ak_recvmsg_exit", "syscalls", "sys_exit_recvmsg"},
	{"ak_db_sendto", "syscalls", "sys_enter_sendto"},
	{"ak_unlinkat", "syscalls", "sys_enter_unlinkat"},
	{"ak_unlink", "syscalls", "sys_enter_unlink"},
	{"ak_renameat2", "syscalls", "sys_enter_renameat2"},
	{"ak_rename", "syscalls", "sys_enter_rename"},
	{"ak_mkdirat", "syscalls", "sys_enter_mkdirat"},
	{"ak_fchmodat", "syscalls", "sys_enter_fchmodat"},
	{"ak_fchownat", "syscalls", "sys_enter_fchownat"},
	{"ak_ptrace", "syscalls", "sys_enter_ptrace"},
	{"ak_kill", "syscalls", "sys_enter_kill"},
	{"ak_setuid", "syscalls", "sys_enter_setuid"},
	{"ak_setreuid", "syscalls", "sys_enter_setreuid"},
	{"ak_stdio_write", "syscalls", "sys_enter_write"},
	{"ak_stdio_read_enter", "syscalls", "sys_enter_read"},
	{"ak_stdio_read_exit", "syscalls", "sys_exit_read"},
}

// Load loads the BPF object and registers self-exclusion.
func Load() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	l := &Loader{coll: coll}
	if err := l.registerSelf(); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Loader) registerSelf() error {
	m := l.coll.Maps["ak_self"]
	if m == nil {
		return fmt.Errorf("ak_self map missing")
	}
	tgid := uint32(os.Getpid())
	var one uint8 = 1
	return m.Put(tgid, one)
}

// AttachTracepoints attaches all tracepoint programs. LSM is attached separately.
func (l *Loader) AttachTracepoints() error {
	for _, t := range tracepointAttach {
		prog := l.coll.Programs[t.prog]
		if prog == nil {
			return fmt.Errorf("program %s missing", t.prog)
		}
		lk, err := link.Tracepoint(t.group, t.name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s/%s: %w", t.group, t.name, err)
		}
		l.links = append(l.links, lk)
	}
	return nil
}

// AttachIOUring attaches the io_uring submission tracepoint best-effort. The
// io_uring_submit_req tracepoint exists only on kernels 6.1+ with io_uring
// enabled, so failure is non-fatal.
func (l *Loader) AttachIOUring() error {
	prog := l.coll.Programs["ak_io_uring_submit"]
	if prog == nil {
		return fmt.Errorf("program ak_io_uring_submit missing")
	}
	lk, err := link.Tracepoint("io_uring", "io_uring_submit_req", prog, nil)
	if err != nil {
		return err
	}
	l.links = append(l.links, lk)
	return nil
}

// AttachKprobes attaches the kprobe programs best-effort. ak_new_task hooks
// wake_up_new_task to arm a new task at birth across every clone flavor (fork/
// vfork/clone3/posix_spawn), covering spawns sched_process_fork misses (e.g. a
// launcher re-spawning a worker). Failure is non-fatal.
func (l *Loader) AttachKprobes() error {
	prog := l.coll.Programs["ak_new_task"]
	if prog == nil {
		return fmt.Errorf("program ak_new_task missing")
	}
	lk, err := link.Kprobe("wake_up_new_task", prog, nil)
	if err != nil {
		return err
	}
	l.links = append(l.links, lk)
	return nil
}

// lsmPrograms are the BPF-LSM enforcement programs, attached best-effort (a
// kernel may lack a given hook). file_open/socket_connect/bprm are the core set;
// the path_* hooks add delete/rename/chmod/chown pre-blocking.
var lsmPrograms = []string{
	"ak_lsm_file_open", "ak_lsm_socket_connect", "ak_lsm_bprm",
	"ak_lsm_path_unlink", "ak_lsm_path_rmdir", "ak_lsm_path_rename",
	"ak_lsm_path_chmod", "ak_lsm_path_chown", "ak_lsm_path_truncate",
	"ak_lsm_task_kill", "ak_lsm_ptrace", "ak_lsm_socket_sendmsg",
}

// coreLSMPrograms are the hooks the pre-operation guarantee rests on. Losing any
// one of them silently voids a whole class of Block decisions, which would still
// be installed into maps that nothing reads: file_open carries the file rules,
// provenance taint and the sensitive-source arm; bprm carries exec; and
// socket_connect carries all egress. Every other hook costs exactly one operation
// and narrows the envelope rather than hollowing it out.
var coreLSMPrograms = map[string]bool{
	"ak_lsm_file_open":      true,
	"ak_lsm_bprm":           true,
	"ak_lsm_socket_connect": true,
}

// MissingCoreLSM names the core hooks among a failed set, in attach order, so the
// caller can demote the backend rather than run an enforcer that cannot enforce.
func MissingCoreLSM(failed map[string]error) []string {
	var out []string
	for _, name := range lsmPrograms {
		if coreLSMPrograms[name] && failed[name] != nil {
			out = append(out, name)
		}
	}
	return out
}

// AttachLSM attaches the BPF-LSM programs best-effort. It returns an error only
// if none attached (caller then falls back to observe-only). Individual failures
// are reported via failed.
func (l *Loader) AttachLSM() (attached []string, failed map[string]error) {
	failed = map[string]error{}
	for _, name := range lsmPrograms {
		prog := l.coll.Programs[name]
		if prog == nil {
			failed[name] = fmt.Errorf("program missing")
			continue
		}
		lk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			failed[name] = err
			continue
		}
		l.links = append(l.links, lk)
		attached = append(attached, name)
	}
	return attached, failed
}

// Map accessors shared with the enforcer.
func (l *Loader) SessionMap() *ebpf.Map             { return l.coll.Maps["ak_sessions"] }
func (l *Loader) SessionPidsMap() *ebpf.Map         { return l.coll.Maps["ak_session_pids"] }
func (l *Loader) AgentSigsMap() *ebpf.Map           { return l.coll.Maps["ak_agent_sigs"] }
func (l *Loader) EnforceFileMap() *ebpf.Map         { return l.coll.Maps["ak_enforce_file"] }
func (l *Loader) EnforceDirMap() *ebpf.Map          { return l.coll.Maps["ak_enforce_dir"] }
func (l *Loader) EnforceNetMap() *ebpf.Map          { return l.coll.Maps["ak_enforce_net"] }
func (l *Loader) EnforceNet6Map() *ebpf.Map         { return l.coll.Maps["ak_enforce_net6"] }
func (l *Loader) PostureMap() *ebpf.Map             { return l.coll.Maps["ak_posture"] }
func (l *Loader) TaintFilesMap() *ebpf.Map          { return l.coll.Maps["ak_taint_files"] }
func (l *Loader) SensitiveFilesMap() *ebpf.Map      { return l.coll.Maps["ak_sensitive_files"] }
func (l *Loader) FlagsMap() *ebpf.Map               { return l.coll.Maps["ak_flags"] }
func (l *Loader) DBDenyTablesMap() *ebpf.Map        { return l.coll.Maps["ak_db_deny_tables"] }
func (l *Loader) EventsMap() *ebpf.Map              { return l.coll.Maps["ak_events"] }
func (l *Loader) SemanticMap() *ebpf.Map            { return l.coll.Maps["ak_semantic"] }
func (l *Loader) Program(name string) *ebpf.Program { return l.coll.Programs[name] }

// Kernel enforcement-fault counters, byte-locked to the AK_ERR_* slots in
// bpf/maps.bpf.h. Each names a fault the hook could not act on and would
// otherwise leave silent.
var KernelFaultNames = [...]string{
	"path_unresolved", // no absolute path could be produced; the operation was refused
	"arm_egress",      // deny-egress could be armed on neither the pid nor the cgroup
	"arm_session",     // a session arming write was rejected (map full); at bprm an enforce-mode exec is refused
	"taint_store",     // a provenance taint could not be stored under its path key
	"db_read",         // an outbound DB payload was unreadable, so the query went unmatched
}

// KernelFaults sums the per-CPU ak_errors counters, one total per AK_ERR_ slot.
func (l *Loader) KernelFaults() ([len(KernelFaultNames)]uint64, error) {
	var out [len(KernelFaultNames)]uint64
	m := l.coll.Maps["ak_errors"]
	if m == nil {
		return out, fmt.Errorf("ak_errors map missing")
	}
	// The names are the only record of what each slot means, so a slot added in
	// the C header without one here would be counted by the kernel and never
	// reported. Compare against the map the object actually carries.
	if got := int(m.MaxEntries()); got != len(out) {
		return out, fmt.Errorf("ak_errors has %d slots but %d are named: KernelFaultNames is out of sync with AK_ERR_SLOTS", got, len(out))
	}
	for i := range out {
		var per []uint64
		if err := m.Lookup(uint32(i), &per); err != nil {
			return out, err
		}
		for _, v := range per {
			out[i] += v
		}
	}
	return out, nil
}

func sessionFlags(enforce bool) uint32 {
	var flags uint32 = 0x1 // monitor
	if enforce {
		flags |= 0x2 // enforce
	}
	return flags
}

// orFlags reads the key's current flag word and writes back the union with want,
// so registering a key never clears bits another writer already set. A plain Put
// downgrades an armed key: the daemon registers a pid for monitoring and upgrades
// it to enforcement in two calls, and a Put between them re-publishes the key as
// MONITOR-only, opening a window in which a write-open or exec escapes both
// enforcement and provenance taint. Returns the flags now in force.
func orFlags(m *ebpf.Map, key any, want uint32) (uint32, error) {
	if m == nil {
		return 0, fmt.Errorf("map missing")
	}
	var cur uint32
	if err := m.Lookup(key, &cur); err == nil {
		if cur&want == want {
			return cur, nil // already carries every requested bit
		}
		want |= cur
	}
	if err := m.Put(key, want); err != nil {
		if errors.Is(err, unix.E2BIG) {
			return 0, fmt.Errorf("%w (map full: %d entries)", err, m.MaxEntries())
		}
		return 0, err
	}
	return want, nil
}

// RegisterSession marks a cgroup as monitored (+enforce). Used as a coarse key
// fallback when the agent has a dedicated cgroup (manageCgroup=true).
func (l *Loader) RegisterSession(cgroupID uint64, enforce bool) error {
	_, err := orFlags(l.SessionMap(), cgroupID, sessionFlags(enforce))
	return err
}

func (l *Loader) UnregisterSession(cgroupID uint64) error {
	return l.SessionMap().Delete(cgroupID)
}

// RegisterPID scopes monitoring/enforcement to a specific process (the agent's
// pid tree) — the precise key used with shared cgroups (manageCgroup=false).
func (l *Loader) RegisterPID(tgid uint32, enforce bool) error {
	_, err := orFlags(l.SessionPidsMap(), tgid, sessionFlags(enforce))
	return err
}

func (l *Loader) UnregisterPID(tgid uint32) error {
	return l.SessionPidsMap().Delete(tgid)
}

// McpFdsMap is the (tgid<<32|fd) -> flags map gating stdio-MCP pipe capture.
func (l *Loader) McpFdsMap() *ebpf.Map { return l.coll.Maps["ak_mcp_fds"] }

func mcpFdKey(tgid uint32, fd uint32) uint64 { return uint64(tgid)<<32 | uint64(fd) }

// RegisterMcpFd marks a (pid, fd) pipe for stdio-MCP capture.
func (l *Loader) RegisterMcpFd(tgid uint32, fd uint32) error {
	var one uint8 = 1
	return l.McpFdsMap().Put(mcpFdKey(tgid, fd), one)
}

// UnregisterMcpFd stops capturing a (pid, fd) pipe.
func (l *Loader) UnregisterMcpFd(tgid uint32, fd uint32) error {
	return l.McpFdsMap().Delete(mcpFdKey(tgid, fd))
}

const flagMcpArmed uint32 = 0x2 // AK_FLAG_MCP_ARMED in bpf/maps.bpf.h

// SetMcpArmed arms/disarms the stdio-MCP capture hooks. When disarmed, the global
// write/read hooks return after a single cheap array lookup.
func (l *Loader) SetMcpArmed(on bool) error {
	m := l.FlagsMap()
	if m == nil {
		return fmt.Errorf("ak_flags map missing")
	}
	var key, cur uint32
	_ = m.Lookup(key, &cur)
	next := cur
	if on {
		next |= flagMcpArmed
	} else {
		next &^= flagMcpArmed
	}
	if next == cur {
		return nil
	}
	return m.Put(key, next)
}

// Close detaches links and closes the collection.
func (l *Loader) Close() error {
	for _, lk := range l.links {
		_ = lk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return nil
}
