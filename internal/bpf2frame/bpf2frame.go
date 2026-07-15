// SPDX-License-Identifier: Apache-2.0
// Package bpf2frame decodes raw ring-buffer samples (byte-locked to
// bpf/wire.bpf.h) into typed events, and maps syscall ids to semantics.
package bpf2frame

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/boanlab/agentknox/pkg/types"
)

// HeaderSize is the packed sizeof(struct event_t) from wire.bpf.h.
const HeaderSize = 88

// Pseudo syscall ids (must match wire.bpf.h).
const (
	pseudoSchedExit = 1001
	pseudoDNSAnswer = 1002
	pseudoTLSRead   = 1003
	pseudoTLSWrite  = 1004
	pseudoLSMFile   = 1005
	pseudoDNSQuery  = 1007
	pseudoLSMExec   = 1008
	pseudoPersist   = 1009
	pseudoIOUring   = 1010
)

// Header mirrors struct event_t.
type Header struct {
	EventType int8
	Category  int8
	CPUID     uint16
	DataLen   uint32
	Timestamp uint64
	CgroupID  uint64
	HostPPID  int32
	HostPID   int32
	HostTID   int32
	PID       int32
	TID       int32
	UID       uint32
	GID       uint32
	PidNS     uint32
	MntNS     uint32
	SyscallID int32
	RetVal    int64
	Comm      string
}

// Frame is a decoded header plus its trailing payload.
type Frame struct {
	Header  Header
	Payload []byte
}

var le = binary.LittleEndian

// Decode parses one ring sample into a Frame.
func Decode(b []byte) (*Frame, error) {
	if len(b) < HeaderSize {
		return nil, fmt.Errorf("short sample: %d < %d", len(b), HeaderSize)
	}
	h := Header{
		EventType: int8(b[0]),
		Category:  int8(b[1]),
		CPUID:     le.Uint16(b[2:]),
		DataLen:   le.Uint32(b[4:]),
		Timestamp: le.Uint64(b[8:]),
		CgroupID:  le.Uint64(b[16:]),
		HostPPID:  int32(le.Uint32(b[24:])),
		HostPID:   int32(le.Uint32(b[28:])),
		HostTID:   int32(le.Uint32(b[32:])),
		PID:       int32(le.Uint32(b[36:])),
		TID:       int32(le.Uint32(b[40:])),
		UID:       le.Uint32(b[44:]),
		GID:       le.Uint32(b[48:]),
		PidNS:     le.Uint32(b[52:]),
		MntNS:     le.Uint32(b[56:]),
		SyscallID: int32(le.Uint32(b[60:])),
		RetVal:    int64(le.Uint64(b[64:])),
		Comm:      cstr(b[72:88]),
	}
	f := &Frame{Header: h}
	if h.DataLen > 0 && len(b) >= HeaderSize {
		end := HeaderSize + int(h.DataLen)
		if end > len(b) {
			end = len(b)
		}
		f.Payload = b[HeaderSize:end]
	}
	return f, nil
}

// MapSyscall converts a system-ring frame into a SyscallEvent (pre-enrichment).
func MapSyscall(f *Frame) types.SyscallEvent {
	h := f.Header
	ev := types.SyscallEvent{
		EventID:     newEventID(),
		TimestampNS: h.Timestamp,
		Time:        BootTime(h.Timestamp),
		CPUID:       uint32(h.CPUID),
		HostPPID:    h.HostPPID,
		HostPID:     h.HostPID,
		HostTID:     h.HostTID,
		PID:         h.PID,
		TID:         h.TID,
		UID:         h.UID,
		GID:         h.GID,
		CgroupID:    h.CgroupID,
		PidNS:       h.PidNS,
		MntNS:       h.MntNS,
		SyscallID:   h.SyscallID,
		Comm:        h.Comm,
		RetVal:      h.RetVal,
	}
	name, cat, op := classify(h.SyscallID)
	ev.Name = name
	ev.Category = cat
	ev.Operation = op

	switch {
	case h.SyscallID == pseudoIOUring:
		// RetVal carries the IORING_OP opcode; surface the underlying op name.
		ev.Resource = ioUringOpName(h.RetVal)
		ev.Operation = "io_uring:" + ev.Resource
	case h.SyscallID == pseudoDNSQuery:
		qname := parseDNSQName(f.Payload)
		ev.Resource = qname
		if qname != "" {
			ev.DNS = &types.DNSInfo{QName: qname}
		}
	case h.SyscallID == pseudoDNSAnswer:
		if dns := parseDNSAnswer(f.Payload); dns != nil {
			ev.DNS = dns
			ev.Resource = dns.QName
		}
	case cat == types.CategoryNetwork:
		ev.Resource = decodeSockaddr(f.Payload)
	default:
		if s := cstr(f.Payload); s != "" {
			ev.Resource = s
			ev.ExePath = s
		}
	}
	if cat == types.CategoryFile {
		ev.ExePath = ""
		ev.Resource = cstr(f.Payload)
		// RetVal carries the openat flags, captured at syscall enter.
		if h.RetVal&0x1 != 0 || h.RetVal&0x2 != 0 || h.RetVal&0100 != 0 {
			ev.Operation = "write"
		} else {
			ev.Operation = "read"
		}
	}
	return ev
}

// MapSemantic converts a semantic-ring frame into a SemanticChunk.
func MapSemantic(f *Frame) types.SemanticChunk {
	h := f.Header
	dir := types.DirOutbound
	if h.SyscallID == pseudoTLSRead || h.Category == 1 {
		dir = types.DirInbound
	}
	payload := make([]byte, len(f.Payload))
	copy(payload, f.Payload)
	return types.SemanticChunk{
		TimestampNS: h.Timestamp,
		HostTID:     h.HostTID,
		HostPID:     h.HostPID,
		CgroupID:    h.CgroupID,
		Direction:   dir,
		ConnID:      uint64(h.RetVal), // connection id (SSL*/tls.Conn ptr) for demux
		Bytes:       payload,
	}
}

// classify maps a syscall/pseudo id to (name, category, operation).
func classify(id int32) (string, types.Category, string) {
	switch id {
	case 59:
		return "execve", types.CategoryProcess, "exec"
	case 322:
		return "execveat", types.CategoryProcess, "exec"
	case pseudoSchedExit:
		return "sched_exit", types.CategoryProcess, "exit"
	case 257:
		return "openat", types.CategoryFile, "open"
	case 437:
		return "openat2", types.CategoryFile, "open"
	case pseudoLSMFile:
		return "lsm_file_open", types.CategoryFile, "open"
	case 42:
		return "connect", types.CategoryNetwork, "connect"
	case 87:
		return "unlink", types.CategoryFile, "delete"
	case 263:
		return "unlinkat", types.CategoryFile, "delete"
	case 82:
		return "rename", types.CategoryFile, "rename"
	case 316:
		return "renameat2", types.CategoryFile, "rename"
	case 258:
		return "mkdirat", types.CategoryFile, "mkdir"
	case 268:
		return "fchmodat", types.CategoryFile, "chmod"
	case 260:
		return "fchownat", types.CategoryFile, "chown"
	case 101:
		return "ptrace", types.CategoryProcess, "ptrace"
	case 62:
		return "kill", types.CategoryProcess, "kill"
	case 105:
		return "setuid", types.CategoryCapability, "setuid"
	case 113:
		return "setreuid", types.CategoryCapability, "setuid"
	case pseudoDNSQuery:
		return "dns_query", types.CategoryDNS, "resolve"
	case pseudoDNSAnswer:
		return "dns_answer", types.CategoryDNS, "resolve"
	case pseudoLSMExec:
		return "lsm_bprm", types.CategoryProcess, "exec"
	case pseudoPersist:
		return "persist_exec", types.CategoryProcess, "persist-exec"
	case pseudoIOUring:
		return "io_uring_submit", types.CategoryProcess, "io_uring"
	default:
		return fmt.Sprintf("syscall_%d", id), types.CategoryProcess, "unknown"
	}
}

// decodeSockaddr parses the [family u16][port be16][addr] payload. An AF_UNIX
// address carries a zero port and its filesystem path in place of the address; it
// is rendered as unix:<path> so a local database socket reads like the ip:port
// destinations beside it.
func decodeSockaddr(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	family := le.Uint16(p[0:])
	port := binary.BigEndian.Uint16(p[2:])
	switch family {
	case 1: // AF_UNIX
		path := cstr(p[4:])
		if path == "" {
			return "unix:<abstract>" // abstract or unnamed socket: no filesystem path
		}
		return "unix:" + path
	case 2: // AF_INET
		if len(p) < 8 {
			return ""
		}
		ip := net.IP(p[4:8])
		return fmt.Sprintf("%s:%d", ip.String(), port)
	case 10: // AF_INET6
		if len(p) < 20 {
			return ""
		}
		ip := net.IP(p[4:20])
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return fmt.Sprintf("family_%d", family)
	}
}

// HashString is fnv1a-64, byte-identical to ak_fnv1a in bpf/helpers.bpf.h.
// The kernel hashes the full fixed 256-byte buffer (NUL-padded), so we do too.
func HashString(s string) uint64 {
	var h uint64 = 0xcbf29ce484222325
	buf := make([]byte, 256)
	copy(buf, s)
	for i := 0; i < 256; i++ {
		c := buf[i]
		if c == 0 {
			break
		}
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return h
}

// parseDNSQName extracts the queried domain from a DNS message payload
// (header is 12 bytes; the question's QNAME is a sequence of length-prefixed
// labels terminated by a zero byte).
func parseDNSQName(p []byte) string {
	if len(p) < 13 {
		return ""
	}
	q := p[12:] // skip DNS header
	var labels []string
	for i := 0; i < len(q); {
		n := int(q[i])
		if n == 0 {
			break
		}
		if n&0xc0 != 0 { // compression pointer — unexpected in a query
			break
		}
		i++
		if i+n > len(q) {
			break
		}
		labels = append(labels, string(q[i:i+n]))
		i += n
		if len(labels) > 16 {
			break
		}
	}
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += "."
		}
		out += l
	}
	return out
}

// parseDNSAnswer parses a DNS response payload into the queried name plus its A
// (type 1) and AAAA (type 28) address records. It follows compression pointers
// within the message and is defensive against truncation (the payload is capped
// at 256 bytes by the BPF side, so long answer sets may be partial).
func parseDNSAnswer(p []byte) *types.DNSInfo {
	if len(p) < 12 {
		return nil
	}
	flags := uint16(p[2])<<8 | uint16(p[3])
	if flags&0x8000 == 0 { // not a response
		return nil
	}
	qd := int(p[4])<<8 | int(p[5])
	an := int(p[6])<<8 | int(p[7])
	off := 12

	// Question section: read the first QNAME, skip the rest.
	qname, next, ok := readDNSName(p, off)
	if !ok {
		return nil
	}
	off = next + 4 // QTYPE(2) + QCLASS(2)
	for i := 1; i < qd; i++ {
		_, n, ok := readDNSName(p, off)
		if !ok {
			return nil
		}
		off = n + 4
	}

	info := &types.DNSInfo{QName: qname}
	for i := 0; i < an && off < len(p); i++ {
		_, n, ok := readDNSName(p, off)
		if !ok {
			break
		}
		off = n
		if off+10 > len(p) {
			break
		}
		rtype := int(p[off])<<8 | int(p[off+1])
		ttl := uint32(p[off+4])<<24 | uint32(p[off+5])<<16 | uint32(p[off+6])<<8 | uint32(p[off+7])
		rdlen := int(p[off+8])<<8 | int(p[off+9])
		off += 10
		if off+rdlen > len(p) {
			break
		}
		switch {
		case rtype == 1 && rdlen == 4:
			ip := net.IP(p[off : off+4])
			info.Answers = append(info.Answers, types.DNSAnswer{IP: ip.String(), TTL: ttl})
		case rtype == 28 && rdlen == 16:
			ip := net.IP(p[off : off+16])
			info.Answers = append(info.Answers, types.DNSAnswer{IP: ip.String(), TTL: ttl})
		}
		off += rdlen
	}
	if qname == "" {
		return nil
	}
	return info
}

// readDNSName decodes a (possibly compression-pointer) DNS name starting at off,
// returning the dotted name and the offset just past the name in the record
// stream (for pointer names, the offset after the 2-byte pointer).
func readDNSName(p []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	next := off
	for depth := 0; depth < 32; depth++ {
		if off >= len(p) {
			return "", 0, false
		}
		n := int(p[off])
		if n == 0 {
			if !jumped {
				next = off + 1
			}
			break
		}
		if n&0xc0 == 0xc0 { // compression pointer
			if off+1 >= len(p) {
				return "", 0, false
			}
			if !jumped {
				next = off + 2
			}
			off = (n&0x3f)<<8 | int(p[off+1])
			jumped = true
			continue
		}
		off++
		if off+n > len(p) {
			return "", 0, false
		}
		labels = append(labels, string(p[off:off+n]))
		off += n
		if len(labels) > 16 {
			break
		}
	}
	return strings.Join(labels, "."), next, true
}

func newEventID() string { return types.NewEventID() }

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

var (
	bootOffsetOnce sync.Once
	bootOffsetNs   int64
	bootOffsetOK   bool
)

// computeBootOffset measures the offset between CLOCK_MONOTONIC (which
// bpf_ktime_get_ns uses) and wall-clock, once.
func computeBootOffset() {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return
	}
	bootOffsetNs = time.Now().UnixNano() - ts.Nano()
	bootOffsetOK = true
}

// ioUringOpNames maps the security-relevant IORING_OP_* opcodes to a name; other
// opcodes render as "op_<n>".
var ioUringOpNames = map[int64]string{
	9: "sendmsg", 10: "recvmsg", 13: "accept", 16: "connect", 18: "openat",
	19: "close", 22: "read", 23: "write", 26: "send", 27: "recv", 28: "openat2",
	30: "splice", 34: "shutdown", 35: "renameat", 36: "unlinkat", 37: "mkdirat",
	38: "symlinkat", 39: "linkat", 40: "msg_ring", 46: "socket",
}

func ioUringOpName(opcode int64) string {
	if n, ok := ioUringOpNames[opcode]; ok {
		return n
	}
	return fmt.Sprintf("op_%d", opcode)
}

// BootTime converts a bpf_ktime_get_ns (CLOCK_MONOTONIC) stamp to wall-clock time
// using a one-shot monotonic→wall offset. Falls back to now() if the clock read
// fails or the stamp is absent.
func BootTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Now()
	}
	bootOffsetOnce.Do(computeBootOffset)
	if !bootOffsetOK {
		return time.Now()
	}
	return time.Unix(0, int64(ns)+bootOffsetNs)
}
