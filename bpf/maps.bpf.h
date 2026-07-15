// SPDX-License-Identifier: GPL-2.0
// maps.bpf.h — all BPF maps, looked up by name from the Go loader.
#pragma once

// Main system-event ring buffer (process/file/net/cap/lsm).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} ak_events SEC(".maps");

// Semantic ring buffer (TLS plaintext chunks from uprobes). Sized large: each
// record reserves a full AK_TLS_MAX buffer and streamed responses burst many
// chunks in flight.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} ak_semantic SEC(".maps");

// Registered sessions: cgroup_id -> flags.
//   bit0 = monitored (detailed capture), bit1 = enforce.
#define AK_SESS_MONITOR 0x1
#define AK_SESS_ENFORCE 0x2
// bit2 deny-tainted-code: block exec/interpreter-read of agent-written files. Carried
// in the SESSION flags (not a per-cgroup posture) so it fork-propagates to the whole
// agent process tree and stays consistent even when a multi-process agent (e.g. Claude
// Code) sprawls across several managed cgroups, and so it is armed at exec time before
// the agent's first write.
#define AK_SESS_DENY_CODE 0x4
// bit3 deny-egress: refuses outbound connects. Like DENY_CODE it lives in the
// SESSION flags (not just the per-cgroup posture) so it fork-propagates to the
// process the agent spawns to exfiltrate (e.g. a `curl` child of a tainted
// node worker); the per-cgroup posture alone misses that child across
// cgroups. Set on the tainting process when a session reads a user-unseen
// secret.
#define AK_SESS_DENY_EGRESS 0x8
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 4096);
} ak_sessions SEC(".maps");

// Self-exclusion: AgentKnox's own tgids.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 64);
} ak_self SEC(".maps");

// Per-pid session membership: tgid -> flags. Scopes monitoring/enforcement to an
// agent's process tree even when the cgroup is SHARED with other processes
// (manageCgroup=false default). Checked before the cgroup map (more specific).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 65536);
} ak_session_pids SEC(".maps");

// Agent signatures: fnv1a(exe basename) -> session flags applied on exec by
// the bprm hook (in-kernel tagging; rationale in enforcer.bpf.c). Value is
// MONITOR or MONITOR|ENFORCE.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 64);
} ak_agent_sigs SEC(".maps");

// Per-session security posture: cgroup_id -> flags.
//   bit0 deny-all-egress (semantic-derived escalation, e.g. tainted session)
//   bit1 deny-tainted-code (block exec AND interpreter-read of agent-written code)
#define AK_POSTURE_DENY_EGRESS       0x1
#define AK_POSTURE_DENY_TAINTED_CODE 0x2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 4096);
} ak_posture SEC(".maps");

// Provenance taint: fnv1a-64(absolute path) -> taint bits. Populated by
// userspace as the agent writes/chmods files.
//   AK_TAINT_WRITTEN: the agent wrote this file (content-agnostic provenance);
//                     bprm blocks direct exec of any such file.
//   AK_TAINT_CODE:    additionally detected as code (shebang / exec-bit /
//                     extension); file_open blocks interpreter read of it.
#define AK_TAINT_WRITTEN 0x1
#define AK_TAINT_CODE    0x2
#define AK_TAINT_PERSIST 0x4 // agent-registered persistence artifact (cron/systemd/hook)
// LRU hash: a write-heavy session cannot exhaust the map since the kernel
// evicts cold entries. Live taints stay hot because every bprm/file_open
// lookup on a tainted path refreshes its recency; a file written but never
// executed ages out.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 65536);
} ak_taint_files SEC(".maps");

// Per-inode provenance taint (BPF inode local storage), keyed on the inode
// rather than its path. Complements the path-hash ak_taint_files map on two
// axes: (1) path aliasing (a hard link, rename, or second mount-namespace name
// for the same file resolves to the same inode); (2) exhaustion (per-inode
// storage is freed with the inode, not evicted under map pressure, unlike an
// LRU path entry). A read or exec of an agent-written file is denied if
// either key reports the taint. The path-hash map is retained because it
// survives inode-cache reload, needed for delayed-execution PERSIST
// attribution (out-of-tree cron/systemd).
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} ak_taint_inode SEC(".maps");

// ak_sensitive_files: daemon-populated set of sensitive source paths (fnv1a of
// the absolute path -> 1): developer secrets that must never be exfiltrated
// (credentials, private keys, .env, ~/.ssh, ~/.aws). A monitored agent's
// read-open of one of these arms AK_SESS_DENY_EGRESS on the reading pid
// synchronously in ak_lsm_file_open (the LSM file_open/socket_connect hooks
// fire for io_uring, unlike syscall tracepoints). Populated at session
// detection, keyed identically to ak_taint_files so userspace HashString
// matches the in-kernel ak_fnv1a(d_path).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 8192);
} ak_sensitive_files SEC(".maps");

// Global control flags (single entry). Lets cheap in-kernel gates avoid work when
// a feature is unused (e.g. skip the global bprm d_path unless a persistence
// artifact has been registered).
#define AK_FLAG_PERSIST_ARMED 0x1 // >=1 persistence artifact tainted (arms bprm observe)
#define AK_FLAG_MCP_ARMED     0x2 // >=1 stdio-MCP pipe fd registered (arms write/read capture)
#define AK_FLAG_DB_ARMED      0x4 // >=1 DB socket fd registered (arms outbound-write capture)
#define AK_FLAG_DB_BLOCK_ARMED 0x8 // >=1 denied DB table installed (arms pre-op query block)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} ak_flags SEC(".maps");

// Network egress enforcement: LPM trie of denied IPv4 prefixes -> action.
struct ak_lpm_key {
	__u32 prefixlen;
	__u8  addr[4];
};
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ak_lpm_key);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ak_enforce_net SEC(".maps");

// Network egress enforcement: LPM trie of denied IPv6 prefixes -> action.
struct ak_lpm_key6 {
	__u32 prefixlen;
	__u8  addr[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ak_lpm_key6);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ak_enforce_net6 SEC(".maps");

// File enforcement: fnv1a-64(absolute path) -> forbidden-op bitmask (AK_OP_*).
// Userspace (policy engine) fills this from user-defined "the tool may not do X"
// security rules. Each LSM hook checks its own op bit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 8192);
} ak_enforce_file SEC(".maps");

// Directory-prefix enforcement: fnv1a-64(absolute dir path, no trailing slash)
// -> forbidden-op bitmask. The LSM hooks check every ancestor directory of the
// target path against this map (single incremental-hash pass).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 8192);
} ak_enforce_dir SEC(".maps");

// Registered stdio-MCP pipe fds: (tgid<<32 | fd) -> flags. Userspace registers a
// candidate MCP server's stdin(0)/stdout(1) pipe fds; the stdio hooks capture ONLY
// these (keeps read/write capture off the global syscall hot path).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 4096);
} ak_mcp_fds SEC(".maps");

// Per-thread stash of a pipe read() buffer pointer, for the read-exit hook.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);   // pid_tgid
	__type(value, __u64); // buf ptr
	__uint(max_entries, 8192);
} ak_pipe_read_args SEC(".maps");

// DNS sockets: (tgid<<32 | fd) -> 1. A monitored session's socket is marked here
// when it sends to (or connects to) UDP port 53, so the recvfrom-exit hook knows
// to capture the response payload (and only DNS responses) for FQDN resolution.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 4096);
} ak_dns_fds SEC(".maps");

// Per-thread stash of a recvfrom() buffer pointer for a DNS socket, for the
// recvfrom-exit hook.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);   // pid_tgid
	__type(value, __u64); // buf ptr
	__uint(max_entries, 8192);
} ak_dns_read_args SEC(".maps");

// DB sockets: (tgid<<32 | fd) -> 1. Marked on connect to a DB port
// (5432/3306/27017-9); outbound-write hooks lift plaintext wire queries into
// the semantic ring.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 4096);
} ak_db_fds SEC(".maps");

// ak_db_deny_tables: policy-installed denied DB table names (a system-predicate
// dbTable rule with a Block effect). A COM_QUERY whose SQL contains one of these
// is refused pre-operation. Each entry: byte length + lowercased name.
struct ak_db_pat {
	__u32 len;
	char pat[32];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ak_db_pat);
	__uint(max_entries, 4);
} ak_db_deny_tables SEC(".maps");

// ak_db_deny_pending: tgid -> 1, set by the DB-write capture when the outbound
// query matches a denied table, consumed (and cleared) by the socket_sendmsg
// LSM hook in the same syscall to refuse the send with -EPERM.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1024);
} ak_db_deny_pending SEC(".maps");

// ak_path_scratch: per-CPU AK_PATH_MAX buffer that every d_path resolution writes
// into. The BPF stack holds 512 bytes in total, so a stack buffer caps paths at
// ~255 bytes (bpf_d_path yields -ENAMETOOLONG beyond it) and lets a target under a
// deep tree escape rule matching, provenance taint, and the sensitive-source arm at
// once. LSM programs run with preemption disabled, so a per-CPU slot is not
// re-entered while a hook holds it.
struct ak_path_buf {
	char b[AK_PATH_MAX];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ak_path_buf);
	__uint(max_entries, 1);
} ak_path_scratch SEC(".maps");

// ak_errors: per-CPU counters for enforcement faults that are otherwise silent —
// a path that could not be resolved at all, an arming write the kernel could not
// record (map exhaustion), a provenance taint that could not be stored, and a DB
// payload the hook could not read. The daemon reads and reports them, so a degraded
// envelope is observable rather than inferred.
#define AK_ERR_PATH_UNRESOLVED 0
#define AK_ERR_ARM_EGRESS      1
#define AK_ERR_ARM_SESSION     2
#define AK_ERR_TAINT_STORE     3
#define AK_ERR_DB_READ         4
#define AK_ERR_SLOTS           5
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, AK_ERR_SLOTS);
} ak_errors SEC(".maps");

// ak_db_scratch: per-CPU scratch buffer for the DB query matcher payload. Holding
// it off the stack keeps the BPF-to-BPF combined stack under the 512-byte limit.
struct ak_db_buf {
	char b[64];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ak_db_buf);
	__uint(max_entries, 1);
} ak_db_scratch SEC(".maps");

