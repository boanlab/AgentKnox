// SPDX-License-Identifier: GPL-2.0
// wire.bpf.h — on-ring wire format shared by all BPF programs and byte-locked to
// the Go decoder in internal/bpf2frame. Changing any layout here REQUIRES a
// matching change in the Go decoder.
#pragma once

#define AK_TASK_COMM_LEN 16
#define AK_MAX_STR 256
// AK_PATH_MAX bounds absolute-path resolution and every hash/rule scan derived
// from it, so a target under a deep tree is matched in full rather than escaping a
// deny rule, a provenance taint, and the sensitive-source arm at once. The buffer
// lives in the per-CPU ak_path_scratch map, not on the 512-byte BPF stack. The
// ceiling is the verifier's complexity budget: the scan loops are bounded by this
// constant and file_open runs several of them, so past ~1.5 KiB that program is
// unverifiable on 6.8; 1 KiB keeps margin. A longer path fails CLOSED (the hooks
// refuse it for an enforce-mode session and record AK_ERR_PATH_UNRESOLVED).
// AK_MAX_STR still bounds the ring payload, so a long path is enforced in full and
// reported truncated.
#define AK_PATH_MAX 1024
// TLS/pipe plaintext chunks need a much larger buffer than paths: an HTTP request
// (headers + JSON body) or a model response is commonly a few KB in one write.
// 16 KiB matches the maximum TLS record plaintext, so one inbound read is
// captured whole; larger outbound writes are split across chunks and reassembled
// in userspace. Must stay a power of two (used as a mask to bound the copy for
// the verifier).
#define AK_TLS_MAX 16384

// event_type dispatch (byte 0 of every frame).
enum ak_event_type {
	AK_UNARY = 0, // self-contained event (no enter/exit pairing)
	AK_ENTER = 1, // syscall enter half
	AK_EXIT  = 2, // syscall exit half
};

// Pseudo syscall ids (>= 1000) for non-syscall hooks. 1006 is permanently
// reserved (decoder compat).
#define AK_PSEUDO_SCHED_EXIT  1001
#define AK_PSEUDO_DNS_ANSWER  1002 // DNS response payload (A/AAAA records)
#define AK_PSEUDO_TLS_READ    1003
#define AK_PSEUDO_TLS_WRITE   1004
#define AK_PSEUDO_LSM_FILE    1005
#define AK_PSEUDO_DNS_QUERY   1007
#define AK_PSEUDO_LSM_EXEC    1008
#define AK_PSEUDO_PERSIST_EXEC 1009 // out-of-tree exec of an agent-written persistence artifact
#define AK_PSEUDO_IO_URING    1010 // io_uring SQE submission (retval = opcode)

// Forbidden-operation bitmask, stored as the value in ak_enforce_file (exact
// absolute path) and ak_enforce_dir (directory prefix). Each LSM hook checks its
// own bit, so a policy can forbid distinct operations on the same path/tree.
#define AK_OP_OPEN   0x1
#define AK_OP_EXEC   0x2
#define AK_OP_DELETE 0x4
#define AK_OP_RENAME 0x8
#define AK_OP_CHMOD  0x10
#define AK_OP_CHOWN  0x20
#define AK_OP_WRITE  0x40 // write-open specifically (read-opens still allowed)

// Category enum mirrored in pkg/types.Category.
enum ak_category {
	AK_CAT_PROCESS = 0,
	AK_CAT_FILE    = 1,
	AK_CAT_NETWORK = 2,
	AK_CAT_CAP     = 3,
	AK_CAT_DNS     = 4,
};

// event_t is the 96-byte packed header written to the ring buffer. Variable
// argument data (paths, addrs) follows the header, length in data_len.
struct event_t {
	__s8  event_type;
	__s8  category;
	__u16 cpu_id;
	__u32 data_len;      // bytes of trailing arg payload

	__u64 timestamp;     // bpf_ktime_get_ns

	__u64 cgroup_id;     // primary attribution key

	__s32 host_ppid;
	__s32 host_pid;
	__s32 host_tid;
	__s32 pid;           // namespaced
	__s32 tid;

	__u32 uid;
	__u32 gid;
	__u32 pid_ns;
	__u32 mnt_ns;

	__s32 syscall_id;    // real nr or AK_PSEUDO_*
	__s64 retval;

	char  comm[AK_TASK_COMM_LEN];
} __attribute__((packed));
