// SPDX-License-Identifier: Apache-2.0
//go:build linux

package sensor_test

// Root-gated kernel functional tests for the enforcement/attribution paths.
// They load the real BPF object, attach the LSM + tracepoint programs, and drive
// a child process to confirm each mechanism denies/attributes as designed. They
// skip when not run as root or when a required facility is missing.

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/internal/enforce"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/internal/sensor"
	"github.com/boanlab/agentknox/pkg/types"
)

func loadAttached(t *testing.T) *sensor.Loader {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	l, err := sensor.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := l.AttachTracepoints(); err != nil {
		l.Close()
		t.Fatalf("tracepoints: %v", err)
	}
	if _, failed := l.AttachLSM(); len(failed) > 0 {
		l.Close()
		t.Fatalf("attach lsm: %v", failed)
	}
	return l
}

func newEnforcer(l *sensor.Loader) *enforce.BPFEnforcer {
	return enforce.New(enforce.Maps{
		Sessions: l.SessionMap(), SessionPids: l.SessionPidsMap(),
		EnforceFile: l.EnforceFileMap(), EnforceDir: l.EnforceDirMap(),
		EnforceNet: l.EnforceNetMap(), EnforceNet6: l.EnforceNet6Map(),
		Posture: l.PostureMap(), TaintFiles: l.TaintFilesMap(), Flags: l.FlagsMap(),
		DBDenyTables: l.DBDenyTablesMap(),
	}, false, zap.NewNop())
}

// waitReadyRun releases a child (which blocks on the ready file) and returns its
// single-line output.
func waitReadyRun(t *testing.T, l *sensor.Loader, cmd *exec.Cmd, ready, out string) string {
	t.Helper()
	if err := l.RegisterPID(uint32(cmd.Process.Pid), true); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(ready, []byte("go"), 0644)
	_ = cmd.Wait()
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(out); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

// TestSelfProtection: an enforce-mode member cannot write a protected path nor
// signal the daemon (this test process, in ak_self).
func TestSelfProtection(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	protected := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(protected, []byte("orig\n"), 0644)
	newEnforcer(l).InstallSelfProtection([]string{protected}, nil)
	if err := os.WriteFile(protected, []byte("daemon\n"), 0644); err != nil {
		t.Fatalf("self-excluded daemon should still write: %v", err)
	}
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
if echo x > "$2" 2>/dev/null; then W=WRITE_OK; else W=WRITE_DENIED; fi
if kill -TERM "$3" 2>/dev/null; then K=KILL_OK; else K=KILL_DENIED; fi
echo "$W $K" > "$4"`
	cmd := exec.Command("bash", "-c", script, "bash", ready, protected, itoaPid(os.Getpid()), out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "WRITE_DENIED KILL_DENIED\n" {
		t.Errorf("self-protection: got %q want WRITE_DENIED KILL_DENIED", got)
	}
}

// TestForkInheritance: a setsid grandchild (reparented) is still enforced.
func TestForkInheritance(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid unavailable")
	}
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	forbidden := filepath.Join(dir, "secret")
	_ = os.WriteFile(forbidden, []byte("orig\n"), 0644)
	_ = l.EnforceFileMap().Put(bpf2frame.HashString(forbidden), uint32(0x1)) // opOpen
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
setsid bash -c 'if echo x > "'"$2"'" 2>/dev/null; then r=OK; else r=DENIED; fi; echo $r > "'"$3"'"'
for i in $(seq 1 100); do [ -s "$3" ] && break; sleep 0.02; done`
	cmd := exec.Command("bash", "-c", script, "bash", ready, forbidden, out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "DENIED\n" {
		t.Errorf("fork inheritance: setsid grandchild not enforced, got %q", got)
	}
}

// TestIPv6Egress: a denied IPv6 prefix blocks connect with EPERM.
func TestIPv6Egress(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	l := loadAttached(t)
	defer l.Close()
	var k struct {
		prefixLen uint32
		addr      [16]byte
	}
	k.prefixLen = 128
	copy(k.addr[:], net.IPv6loopback.To16())
	_ = l.EnforceNet6Map().Put(k, uint32(1))
	dir := t.TempDir()
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	py := `import socket,errno
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
try:
 s.connect(("::1",9)); print("CONNECTED")
except OSError as e: print("EPERM" if e.errno==errno.EPERM else "OTHER")`
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
python3 -c "$2" > "$3" 2>&1`
	cmd := exec.Command("bash", "-c", script, "bash", ready, py, out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "EPERM\n" {
		t.Errorf("ipv6 egress: got %q want EPERM", got)
	}
}

// TestPersistObserveOnly: an out-of-tree tainted persistence artifact still runs
// (observe-only), confirming detection does not block.
func TestPersistObserveOnly(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	art := filepath.Join(dir, "job.sh")
	_ = os.WriteFile(art, []byte("#!/bin/sh\necho ran\n"), 0755)
	newEnforcer(l).TaintPersist(art)
	out, err := exec.Command(art).CombinedOutput()
	if err != nil || string(out) != "ran\n" {
		t.Errorf("persist observe-only must not block: err=%v out=%q", err, out)
	}
}

// deepDir creates a directory tree under root whose absolute path exceeds want
// bytes, and returns it. Each component stays inside NAME_MAX.
func deepDir(t *testing.T, root string, want int) string {
	t.Helper()
	p := root
	for len(p) < want {
		p = filepath.Join(p, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Skipf("cannot build a %d-byte path: %v", want, err)
	}
	return p
}

// TestLongPathEnforcement: a directory rule still matches a target whose absolute
// path far exceeds the hooks' path buffer. Treating d_path's -ENAMETOOLONG as
// "allow" would let a deep tree defeat deny rules, provenance taint, and the
// sensitive-source arm at once.
func TestLongPathEnforcement(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()     // control files, unprotected
	guarded := t.TempDir() // the forbidden tree
	target := filepath.Join(deepDir(t, guarded, 400), "secret")
	if err := os.WriteFile(target, []byte("orig\n"), 0644); err != nil {
		t.Skipf("cannot create the deep target: %v", err)
	}
	// Forbid open under the whole tree; only the ancestor dir hash is installed.
	if err := l.EnforceDirMap().Put(bpf2frame.HashString(guarded), uint32(0x1)); err != nil {
		t.Fatal(err)
	}
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
if cat "$2" >/dev/null 2>&1; then r=ALLOWED; else r=DENIED; fi
echo $r > "$3"`
	cmd := exec.Command("bash", "-c", script, "bash", ready, target, out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "DENIED\n" {
		t.Errorf("long-path rule matching: got %q want DENIED (path is %d bytes)", got, len(target))
	}
}

// TestUnresolvablePathFailsClosed: a path beyond what the hooks can resolve is
// refused for an enforce-mode member rather than allowed unmediated. No rule is
// installed here, so an allow would mean the operation escaped mediation entirely.
func TestUnresolvablePathFailsClosed(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	target := filepath.Join(deepDir(t, dir, 1200), "secret")
	if err := os.WriteFile(target, []byte("orig\n"), 0644); err != nil {
		t.Skipf("cannot create the over-long target: %v", err)
	}
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
if cat "$2" >/dev/null 2>&1; then r=ALLOWED; else r=DENIED; fi
echo $r > "$3"`
	cmd := exec.Command("bash", "-c", script, "bash", ready, target, out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "DENIED\n" {
		t.Errorf("unresolvable path must fail closed: got %q (path is %d bytes)", got, len(target))
	}
	faults, err := l.KernelFaults()
	if err != nil {
		t.Fatalf("kernel faults: %v", err)
	}
	if faults[0] == 0 {
		t.Error("an unresolvable path must be counted, not silently refused")
	}
}

// TestTruncateSelfProtection: truncate(2) opens nothing, so it bypasses the
// write-open gate; path_truncate is the hook that covers a write-protected file.
func TestTruncateSelfProtection(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	protected := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(protected, []byte("orig\n"), 0644); err != nil {
		t.Fatal(err)
	}
	newEnforcer(l).InstallSelfProtection([]string{protected}, nil)
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	py := `import os,sys
try:
 os.truncate(sys.argv[1],0); print("TRUNCATED")
except OSError: print("DENIED")`
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
python3 -c "$2" "$3" > "$4" 2>&1`
	cmd := exec.Command("bash", "-c", script, "bash", ready, py, protected, out)
	_ = cmd.Start()
	if got := waitReadyRun(t, l, cmd, ready, out); got != "DENIED\n" {
		t.Errorf("truncate self-protection: got %q want DENIED", got)
	}
	if b, _ := os.ReadFile(protected); string(b) != "orig\n" {
		t.Errorf("protected file was truncated: %q", b)
	}
}

// TestRegisterPIDPreservesArmedFlags: registering a pid for monitoring must not
// clear bits already in force. The daemon registers then upgrades in two calls,
// and the kernel itself sets deny-egress on the same key at a sensitive read, so a
// plain Put would re-publish an armed pid as MONITOR-only.
func TestRegisterPIDPreservesArmedFlags(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	l, err := sensor.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer l.Close()
	const (
		pid                                           = uint32(0x7fffff01)
		monitor, enforce, denyCode, denyEgress uint32 = 0x1, 0x2, 0x4, 0x8
	)
	if err := l.RegisterPID(pid, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	// The kernel arms deny-egress on the same key when the session reads a secret.
	armed := monitor | enforce | denyCode | denyEgress
	if err := l.SessionPidsMap().Put(pid, armed); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if err := l.RegisterPID(pid, false); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	var got uint32
	if err := l.SessionPidsMap().Lookup(pid, &got); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != armed {
		t.Errorf("monitor-only registration downgraded an armed pid: got %#x want %#x", got, armed)
	}
	// The enforcer's own re-arm sweep must preserve the kernel-set egress arm too.
	newEnforcer(l).EnforcePID(int32(pid))
	if err := l.SessionPidsMap().Lookup(pid, &got); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got&denyEgress == 0 {
		t.Errorf("re-arm cleared the kernel-set deny-egress bit: got %#x", got)
	}
	_ = l.UnregisterPID(pid)
}

// TestMemfdExecDenied: an in-memory image the session wrote never traverses
// file_open, so neither provenance key is ever set on it and exec of it would
// escape the write-then-run gate. Under a provenance policy it is refused on the
// absence of a path.
func TestMemfdExecDenied(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	l := loadAttached(t)
	defer l.Close()
	py := `import os,sys
img = open("/bin/true","rb").read()
fd = os.memfd_create("payload")
os.write(fd, img)
pid = os.fork()
if pid == 0:
    try:
        os.execve("/proc/self/fd/%d" % fd, ["payload"], {})
    except OSError:
        os._exit(7)
    os._exit(0)
print("DENIED" if os.waitpid(pid,0)[1] >> 8 == 7 else "RAN")`
	// MONITOR|ENFORCE alone must not refuse it: the refusal belongs to the
	// provenance policy, and the control is what shows the test exercises it.
	run := func(flags uint32) string {
		dir := t.TempDir()
		ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
		script := `while [ ! -f "$1" ]; do sleep 0.02; done
python3 -c "$2" > "$3" 2>&1`
		cmd := exec.Command("bash", "-c", script, "bash", ready, py, out)
		_ = cmd.Start()
		if err := l.SessionPidsMap().Put(uint32(cmd.Process.Pid), flags); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(ready, []byte("go"), 0644)
		_ = cmd.Wait()
		for i := 0; i < 100; i++ {
			if b, err := os.ReadFile(out); err == nil && len(b) > 0 {
				return string(b)
			}
			time.Sleep(20 * time.Millisecond)
		}
		return ""
	}
	if got := run(0x1 | 0x2); got != "RAN\n" {
		t.Errorf("without the provenance policy, memfd exec must run: got %q", got)
	}
	if got := run(0x1 | 0x2 | 0x4); got != "DENIED\n" {
		t.Errorf("memfd exec under a provenance policy: got %q want DENIED", got)
	}
}

// fillSessionPids writes filler entries into ak_session_pids until the kernel
// refuses one, so the next membership write a hook attempts is rejected. Keys are
// far above pid_max, so no live process is impersonated. Returns how many were
// added.
func fillSessionPids(t *testing.T, l *sensor.Loader) int {
	t.Helper()
	m := l.SessionPidsMap()
	const monitor = uint32(0x1)
	for i := 0; i < 70000; i++ {
		if err := m.Put(uint32(0x40000000+i), monitor); err != nil {
			return i
		}
	}
	t.Skip("ak_session_pids did not fill within 70000 entries")
	return 0
}

// TestArmSessionFailsClosedWhenMapFull: with the per-pid session map full, an exec
// whose membership write the kernel rejects would run outside every hook. The bprm
// hook refuses it for an enforce-mode session rather than starting an unmediated
// member, and counts the fault.
func TestArmSessionFailsClosedWhenMapFull(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	dir := t.TempDir()
	ready, out := filepath.Join(dir, "r"), filepath.Join(dir, "o")
	// The wait loop uses builtins only: an external `sleep` is itself an exec, and
	// this test is about execs being refused.
	script := `while [ ! -f "$1" ]; do :; done
/bin/true 2>/dev/null; echo $? > "$2"`
	cmd := exec.Command("bash", "-c", script, "bash", ready, out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Arm the waiting shell as an enforce-mode member, THEN exhaust the map, so the
	// child it spawns can no longer be recorded.
	if err := l.SessionPidsMap().Put(uint32(cmd.Process.Pid), uint32(0x1|0x2)); err != nil {
		t.Fatal(err)
	}
	before, err := l.KernelFaults()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("filled ak_session_pids with %d entries", fillSessionPids(t, l))
	// Precondition: the next membership write really is rejected. Without this the
	// test could pass for the wrong reason.
	if err := l.SessionPidsMap().Put(uint32(0x50000001), uint32(1)); err == nil {
		t.Fatal("ak_session_pids still accepts a new key; the test cannot exercise the fault")
	}

	_ = os.WriteFile(ready, []byte("go"), 0644)
	_ = cmd.Wait()
	got := ""
	for i := 0; i < 200; i++ {
		if b, err := os.ReadFile(out); err == nil && len(b) > 0 {
			got = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got == "0\n" || got == "" {
		t.Errorf("exec under a full session map must be refused, got exit %q", got)
	}
	after, err := l.KernelFaults()
	if err != nil {
		t.Fatal(err)
	}
	if after[2] <= before[2] {
		t.Errorf("a refused arming write must be counted: arm_session %d -> %d", before[2], after[2])
	}
}

// TestUnixSocketDBRegistered: a database client reaching its server over a unix
// socket carries no TCP port, so the port test cannot see it. The socket name is
// what registers it for capture; a socket naming no database must not.
func TestUnixSocketDBRegistered(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	l := loadAttached(t)
	defer l.Close()

	// Short paths: sun_path holds 108 bytes and t.TempDir() is already deep.
	sockDir, err := os.MkdirTemp("/tmp", "akdbsock")
	if err != nil {
		t.Skipf("cannot create a short socket dir: %v", err)
	}
	defer os.RemoveAll(sockDir)

	serve := func(name string) string {
		p := filepath.Join(sockDir, name)
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Skipf("cannot listen on %s: %v", p, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		return p
	}
	plain := serve("plain.sock")
	dbSock := serve("mysqld.sock")

	py := `import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
print("CONNECTED")`
	connect := func(path string) {
		d := t.TempDir()
		ready, out := filepath.Join(d, "r"), filepath.Join(d, "o")
		script := `while [ ! -f "$1" ]; do sleep 0.02; done
python3 -c "$2" "$3" > "$4" 2>&1`
		cmd := exec.Command("bash", "-c", script, "bash", ready, py, path, out)
		_ = cmd.Start()
		if got := waitReadyRun(t, l, cmd, ready, out); got != "CONNECTED\n" {
			t.Fatalf("connect to %s: %q", path, got)
		}
	}
	dbArmed := func() bool {
		var key, flags uint32
		if err := l.FlagsMap().Lookup(key, &flags); err != nil {
			t.Fatalf("flags lookup: %v", err)
		}
		return flags&0x4 != 0 // AK_FLAG_DB_ARMED
	}

	connect(plain)
	if dbArmed() {
		t.Fatal("a unix socket that names no database must not arm DB capture")
	}
	connect(dbSock)
	if !dbArmed() {
		t.Error("a connect to a database server's unix socket must arm DB capture")
	}
}

// dbProbePy drives four MySQL COM_QUERY sends on one registered DB socket and
// reports the outcome of each. Two are placed on the heap and two so their LAST
// byte is the LAST byte of a page whose successor is PROT_NONE, which is the
// placement a fixed-size payload read faults on. send() is called through libc so
// the buffer the kernel sees is exactly the one placed, with no interpreter copy.
const dbProbePy = `import ctypes, errno, os, socket, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.send.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.send.restype = ctypes.c_ssize_t
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
fd = s.fileno()

def com_query(sql):
    body = b"\x03" + sql.encode()
    return len(body).to_bytes(3, "little") + b"\x00" + body

DENIED = com_query("select * from secrets")
ALLOWED = com_query("select * from invoice")

def send_ptr(ptr, n):
    ctypes.set_errno(0)
    if libc.send(fd, ptr, n, 0) >= 0:
        return "SENT"
    e = ctypes.get_errno()
    return "EPERM" if e == errno.EPERM else "ERRNO_%d" % e

def send_heap(p):
    b = ctypes.create_string_buffer(p, len(p))
    return send_ptr(ctypes.cast(b, ctypes.c_void_p), len(p))

res = {}
res["heap_denied"] = send_heap(DENIED)
res["heap_allowed"] = send_heap(ALLOWED)

PG = os.sysconf("SC_PAGESIZE")
MAP_FAILED = ctypes.c_void_p(-1).value
base = libc.mmap(None, 2 * PG, 0x1 | 0x2, 0x02 | 0x20, -1, 0)
ok = base is not None and base != MAP_FAILED
if ok:
    ok = libc.mprotect(ctypes.c_void_p(base + PG), PG, 0) == 0
if ok:
    def send_page_end(p):
        a = base + PG - len(p)
        ctypes.memmove(ctypes.c_void_p(a), p, len(p))
        return send_ptr(ctypes.c_void_p(a), len(p))
    res["page_denied"] = send_page_end(DENIED)
    res["page_allowed"] = send_page_end(ALLOWED)
else:
    res["page_denied"] = "SETUP_FAILED"
    res["page_allowed"] = "SETUP_FAILED"

for k in ("heap_denied", "heap_allowed", "page_denied", "page_allowed"):
    print("%s=%s" % (k, res[k]))
`

// dbQueryProbe installs a Block rule on the table `secrets`, stands up a fake
// database server on a unix socket whose name registers it for DB capture, and
// runs dbProbePy as an enforce-mode session member against it. It returns each
// send's outcome keyed by name. No real database is needed: a blocked query is
// refused in the sending syscall, before the server can observe it.
func dbQueryProbe(t *testing.T, l *sensor.Loader) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	// Short paths: sun_path holds 108 bytes and t.TempDir() is already deep.
	sockDir, err := os.MkdirTemp("/tmp", "akdbq")
	if err != nil {
		t.Skipf("cannot create a short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "mysqld.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", sockPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()

	if err := newEnforcer(l).InstallRules([]pipeline.KernelRule{{
		PolicyName: "kernel-test-db-block", Category: types.CategoryDatabase,
		Operation: "query", DBEngine: "mysql", DBTable: "secrets",
		Effect: types.EffectBlock,
	}}); err != nil {
		t.Fatalf("install db rule: %v", err)
	}

	d := t.TempDir()
	ready, out := filepath.Join(d, "r"), filepath.Join(d, "o")
	script := `while [ ! -f "$1" ]; do sleep 0.02; done
python3 -c "$2" "$3" > "$4" 2>&1`
	cmd := exec.Command("bash", "-c", script, "bash", ready, dbProbePy, sockPath, out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	raw := waitReadyRun(t, l, cmd, ready, out)
	res := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			res[k] = v
		}
	}
	if len(res) != 4 {
		t.Fatalf("db probe produced %q", raw)
	}
	// Precondition: the socket really registered for DB capture, so an unblocked
	// send below means the query was inspected and permitted, not unwatched.
	var key, flags uint32
	if err := l.FlagsMap().Lookup(key, &flags); err != nil {
		t.Fatalf("flags lookup: %v", err)
	}
	if flags&0x4 == 0 { // AK_FLAG_DB_ARMED
		t.Fatalf("the fake database socket did not arm DB capture (flags %#x)", flags)
	}
	if flags&0x8 == 0 { // AK_FLAG_DB_BLOCK_ARMED
		t.Fatalf("the db deny rule did not arm the pre-op query block (flags %#x)", flags)
	}
	return res
}

// TestDBQueryBlockedPreOperation: a COM_QUERY naming a policy-denied table is
// refused with EPERM in the sending syscall, so it never reaches the server. The
// permitted query on the SAME socket and session must still complete: that
// control is what shows the verdict turns on the parsed statement rather than on
// the socket being registered.
func TestDBQueryBlockedPreOperation(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	res := dbQueryProbe(t, l)
	if res["heap_denied"] != "EPERM" {
		t.Errorf("a query naming a denied table must be refused: got %q", res["heap_denied"])
	}
	if res["heap_allowed"] != "SENT" {
		t.Errorf("a query naming a permitted table must complete: got %q", res["heap_allowed"])
	}
}

// TestDBQueryBlockedAtPageBoundary: a denied query is still refused when its
// buffer ends exactly at a page boundary whose next page is unmapped. Reading a
// fixed scratch-sized window instead of the payload's own length faults on that
// placement in its entirety, and a check that treats an unreadable payload as
// nothing to block would let the query through on its address alone. The
// permitted query at the same placement is the control: it must still send, so a
// refusal here can only come from the parsed table name.
func TestDBQueryBlockedAtPageBoundary(t *testing.T) {
	l := loadAttached(t)
	defer l.Close()
	res := dbQueryProbe(t, l)
	if res["page_allowed"] == "SETUP_FAILED" {
		t.Skip("cannot place a guarded page pair")
	}
	if res["page_allowed"] != "SENT" {
		t.Errorf("a permitted query at a page boundary must complete: got %q", res["page_allowed"])
	}
	if res["page_denied"] != "EPERM" {
		t.Errorf("a denied query whose buffer ends at a page boundary must still be refused: got %q",
			res["page_denied"])
	}
}

// itoaPid formats a pid without pulling strconv into this test file.
func itoaPid(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
