// SPDX-License-Identifier: GPL-2.0
// helpers.bpf.h — shared helpers: attribution, self-exclusion, header fill,
// fnv1a hashing (byte-identical to the Go side), and submit.
#pragma once

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

// fnv1a-64. MUST match internal/bpf2frame.HashString and internal/enforce.
// The loop is bounded by AK_PATH_MAX so it stays inside the verifier's budget.
static __always_inline __u64 ak_fnv1a(const char *buf, int len)
{
	__u64 h = 0xcbf29ce484222325ULL;
	for (int i = 0; i < AK_PATH_MAX; i++) {
		if (i >= len)
			break;
		char c = buf[i];
		if (c == 0)
			break;
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

// AK_BASENAME_MAX bounds the single pass ak_fnv1a_basename makes over the WHOLE
// path, not over the trailing component alone: the hash restarts at every '/', so
// the scan must reach the end of the path for the final segment to be the one that
// survives. It therefore has to match the path bound (AK_MAX_STR), not the length
// of a signature name. A smaller value silently truncates mid-path and yields the
// hash of a partial interior segment, which no signature can match -- that is what
// made in-kernel arming fail for agents installed under a long prefix (nvm, pnpm,
// npm-global).
#define AK_BASENAME_MAX AK_MAX_STR

// ak_fnv1a_basename hashes the final path component of a NUL-terminated path
// (e.g. "/home/boan/go/bin/crush" -> hash of "crush"), matching the userspace hash
// of an agent signature (filepath.Base), so the kernel can recognize an agent
// binary at exec without a userspace round-trip. One bounded pass: each '/' resets
// the running hash to the FNV offset basis, so at NUL it holds the hash of the
// segment after the last '/'. ASCII letters are folded to lower case to match the
// lower-cased signature userspace seeds; without the fold, a binary name carrying
// a capital never matches its own signature and is never armed.
static __always_inline __u64 ak_fnv1a_basename(const char *buf)
{
	__u64 h = 0xcbf29ce484222325ULL;
	for (int i = 0; i < AK_BASENAME_MAX; i++) {
		char c = buf[i];
		if (c == 0)
			break;
		if (c == '/') {
			h = 0xcbf29ce484222325ULL; // restart after the separator
			continue;
		}
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

static __always_inline __u32 ak_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

// ak_bump_err records an enforcement fault the hook could not act on (an
// unresolvable path, an arming write the kernel refused, a taint it could not
// store). Per-CPU, so the increment needs no atomic; the daemon sums and reports.
static __always_inline void ak_bump_err(__u32 slot)
{
	__u64 *c = bpf_map_lookup_elem(&ak_errors, &slot);
	if (c)
		*c += 1;
}

// ak_path_resolve resolves an absolute path into the per-CPU PATH_MAX scratch and
// returns it, or NULL when the kernel could not produce a path at all. The full
// PATH_MAX buffer is what makes rule matching, provenance taint, and the
// sensitive-source arm hold for a target under a deep tree; every caller treats
// NULL as a fault, never as "allow".
static __always_inline char *ak_path_resolve(struct path *p)
{
	__u32 z = 0;
	struct ak_path_buf *s = bpf_map_lookup_elem(&ak_path_scratch, &z);
	if (!s)
		return NULL;
	if (bpf_d_path(p, s->b, sizeof(s->b)) <= 0) {
		ak_bump_err(AK_ERR_PATH_UNRESOLVED);
		return NULL;
	}
	return s->b;
}

// ak_forbidden reports whether operation `op` on absolute path `buf` is forbidden
// by policy. A SINGLE left-to-right pass computes the running fnv1a hash: at each
// '/' boundary it checks the ancestor directory against ak_enforce_dir, and at
// the end the full-path hash against ak_enforce_file. Byte-identical to the Go
// HashString(), so kernel and userspace agree.
static __always_inline int ak_forbidden(const char *buf, __u32 op)
{
	__u64 h = 0xcbf29ce484222325ULL;
	int i;
	for (i = 0; i < AK_PATH_MAX; i++) {
		char c = buf[i];
		if (c == 0)
			break;
		if (c == '/' && i > 0) {
			__u32 *dm = bpf_map_lookup_elem(&ak_enforce_dir, &h);
			if (dm && (*dm & op))
				return 1;
		}
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	__u32 *fm = bpf_map_lookup_elem(&ak_enforce_file, &h);
	if (fm && (*fm & op))
		return 1;
	return 0;
}

#define AK_NAME_MAX 128

// ak_fnv1a_split computes fnv1a-64 of the absolute path <dir>/<name> from two
// separate buffers, without concatenating (verifier-safe), byte-identical to the
// full-file-path hash ak_forbidden_split computes and to ak_fnv1a of a d_path
// result. Used to move provenance taint on rename (old path hash -> new path hash).
static __always_inline __u64 ak_fnv1a_split(const char *dir, const char *name)
{
	__u64 h = 0xcbf29ce484222325ULL;
	char last = 0;
	int i;
	for (i = 0; i < AK_PATH_MAX; i++) {
		char c = dir[i];
		if (c == 0)
			break;
		last = c;
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	// Insert the separator only when dir does not already end in one. bpf_d_path
	// renders the root directory as "/", so appending unconditionally hashed
	// "//name" there and nothing -- no rule, no taint entry -- ever matched a file
	// sitting directly under /. `last` is carried out of the loop rather than
	// re-read as dir[i-1], which keeps this a single bounded pass.
	if (last != '/') {
		h ^= (__u64)(__u8)'/';
		h *= 0x100000001b3ULL;
	}
	for (i = 0; i < AK_NAME_MAX; i++) {
		char c = name[i];
		if (c == 0)
			break;
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

// ak_forbidden_split is ak_forbidden for a path expressed as <dir>/<name> in two
// separate buffers: avoids a variable-offset stack write (verifier-rejected) by
// hashing dir and name incrementally without concatenating. Checks each
// ancestor dir, then the parent dir, then the exact file hash.
static __always_inline int ak_forbidden_split(const char *dir, const char *name, __u32 op)
{
	__u64 h = 0xcbf29ce484222325ULL;
	int i;
	char last = 0;
	for (i = 0; i < AK_PATH_MAX; i++) {
		char c = dir[i];
		if (c == 0)
			break;
		if (c == '/' && i > 0) {
			__u32 *dm = bpf_map_lookup_elem(&ak_enforce_dir, &h);
			if (dm && (*dm & op))
				return 1;
		}
		last = c;
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	// The parent directory itself is an ancestor of the target file.
	__u32 *dm = bpf_map_lookup_elem(&ak_enforce_dir, &h);
	if (dm && (*dm & op))
		return 1;
	// Separator, then the file name -> full-path hash. Skip the separator when dir
	// already ends in one ("/" for the root directory), which otherwise produced
	// "//name" and made rules on root-level files unmatchable. `last` is carried
	// out of the loop rather than re-read as dir[i-1], keeping this a single
	// bounded pass.
	if (last != '/') {
		h ^= (__u64)(__u8)'/';
		h *= 0x100000001b3ULL;
	}
	for (i = 0; i < AK_NAME_MAX; i++) {
		char c = name[i];
		if (c == 0)
			break;
		h ^= (__u64)(__u8)c;
		h *= 0x100000001b3ULL;
	}
	__u32 *fm = bpf_map_lookup_elem(&ak_enforce_file, &h);
	if (fm && (*fm & op))
		return 1;
	return 0;
}

// ak_flags_get returns the global control-flags word (0 if absent).
static __always_inline __u32 ak_flags_get(void)
{
	__u32 z = 0;
	__u32 *f = bpf_map_lookup_elem(&ak_flags, &z);
	return f ? *f : 0;
}

// ak_flags_or_bit sets a bit in the global control-flags word (idempotent). Used
// to arm a capture hook from the kernel side (e.g. on connect to a DB port). The
// read-modify-write is not atomic (BPF lacks a 32-bit atomic-or); a lost concurrent
// update at most delays arming a capture by one event, which is benign here.
static __always_inline void ak_flags_or_bit(__u32 bit)
{
	__u32 z = 0;
	__u32 *f = bpf_map_lookup_elem(&ak_flags, &z);
	if (f) {
		if (!(*f & bit)) {
			__u32 nv = *f | bit;
			bpf_map_update_elem(&ak_flags, &z, &nv, BPF_ANY);
		}
	} else {
		bpf_map_update_elem(&ak_flags, &z, &bit, BPF_ANY);
	}
}

// True if the current task is AgentKnox itself (excluded from all capture).
static __always_inline int ak_is_self(void)
{
	__u32 tgid = ak_tgid();
	return bpf_map_lookup_elem(&ak_self, &tgid) != NULL;
}

// Returns session flags for the current task, or 0 if not part of a session.
// Checks per-pid membership FIRST (precise, scopes within a shared cgroup), then
// falls back to the cgroup map (covers descendants not yet individually tracked).
static __always_inline __u32 ak_session_flags(__u64 *out_cgid)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	if (out_cgid)
		*out_cgid = cgid;
	__u32 tgid = ak_tgid();
	if (bpf_map_lookup_elem(&ak_self, &tgid))
		return 0; // exclude AgentKnox itself
	__u32 *pf = bpf_map_lookup_elem(&ak_session_pids, &tgid);
	if (pf)
		return *pf;
	__u32 *flags = bpf_map_lookup_elem(&ak_sessions, &cgid);
	if (!flags)
		return 0;
	return *flags;
}

// Fill the common header fields for the current task.
static __always_inline void ak_fill_header(struct event_t *e, __u64 cgid,
					   __s32 syscall_id, __s8 category)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 ug = bpf_get_current_uid_gid();

	e->event_type = AK_UNARY;
	e->category = category;
	e->cpu_id = (__u16)bpf_get_smp_processor_id();
	e->data_len = 0;
	e->timestamp = bpf_ktime_get_ns();
	e->cgroup_id = cgid;
	e->host_pid = pt >> 32;
	e->host_tid = (__s32)pt;
	e->host_ppid = 0;
	e->pid = pt >> 32;
	e->tid = (__s32)pt;
	e->uid = (__u32)ug;
	e->gid = ug >> 32;
	e->pid_ns = 0;
	e->mnt_ns = 0;
	e->syscall_id = syscall_id;
	e->retval = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ak_rec is a fixed-size reserved ring record: header + inline payload.
struct ak_rec {
	struct event_t hdr;
	char data[AK_MAX_STR];
};

// Emit one event with an optional resource string (path/addr).
static __always_inline void ak_emit(__u64 cgid, __s32 sid, __s8 cat,
				    __s64 ret, const char *res)
{
	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return;
	ak_fill_header(&r->hdr, cgid, sid, cat);
	r->hdr.retval = ret;
	r->hdr.data_len = 0;
	if (res) {
		long n = bpf_probe_read_user_str(&r->data, sizeof(r->data), res);
		if (n > 0)
			r->hdr.data_len = (__u32)n;
	}
	bpf_ringbuf_submit(r, 0);
}

// Emit with a kernel-space string (already-read buffer).
static __always_inline void ak_emit_kstr(__u64 cgid, __s32 sid, __s8 cat,
					 __s64 ret, const char *res)
{
	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return;
	ak_fill_header(&r->hdr, cgid, sid, cat);
	r->hdr.retval = ret;
	r->hdr.data_len = 0;
	if (res) {
		long n = bpf_probe_read_kernel_str(&r->data, sizeof(r->data), res);
		if (n > 0)
			r->hdr.data_len = (__u32)n;
	}
	bpf_ringbuf_submit(r, 0);
}

// ak_emit_unresolved reports an operation whose target path the kernel could not
// produce. The operation is refused in an enforce-mode session (no rule could be
// matched against it), and the record is what makes that refusal auditable.
static __always_inline void ak_emit_unresolved(__u64 cgid, __s32 sid, __s8 cat)
{
	char m[16] = "<unresolved>";
	ak_emit_kstr(cgid, sid, cat, 0, m);
}

// ak_emit_arm_fault reports an exec whose session-membership write the kernel
// refused (the per-pid map is full). Such an exec is invisible to every later
// hook, so an enforce-mode session refuses it outright; a monitor-only session
// runs it unwatched. Either outcome is a hole in the envelope, so it is reported
// as an event rather than left to a counter the operator has to go looking for.
static __always_inline void ak_emit_arm_fault(__u64 cgid)
{
	char m[16] = "<arm-failed>";
	ak_emit_kstr(cgid, AK_PSEUDO_LSM_EXEC, AK_CAT_PROCESS, 0, m);
}
