// SPDX-License-Identifier: GPL-2.0
// enforcer.bpf.c — BPF-LSM pre-operation enforcement. Denies forbidden file /
// exec / network operations (exact-path or directory-prefix fnv1a match) within
// enforce-mode sessions and emits LSM visibility events.
#pragma once

// ak_deny_code_armed: whether deny-tainted-code is armed for cgid, via the
// fork-propagated session flag or the per-cgroup posture (covers an agent
// that sprawls across managed cgroups and helper processes).
static __always_inline int ak_deny_code_armed(__u32 flags, __u64 cgid)
{
	if (flags & AK_SESS_DENY_CODE)
		return 1;
	__u32 *p = bpf_map_lookup_elem(&ak_posture, &cgid);
	return (p && (*p & AK_POSTURE_DENY_TAINTED_CODE)) ? 1 : 0;
}

// ak_ino_tainted: taint bit from the inode's BPF local storage (the aliasing-
// and eviction-robust provenance key).
static __always_inline int ak_ino_tainted(struct inode *ino, __u32 want)
{
	if (!ino)
		return 0;
	__u32 *t = bpf_inode_storage_get(&ak_taint_inode, ino, 0, 0);
	return (t && (*t & want)) ? 1 : 0;
}

// ak_deny_taint checks BOTH provenance keys: the path-hash map (survives inode-cache
// reload) and the inode's local storage (survives hard link / rename / mount-ns
// aliasing and the path-map's LRU eviction). Denies if EITHER reports the taint.
static __always_inline int ak_deny_taint(const char *buf, struct inode *ino,
					 __u32 flags, __u64 cgid, __u32 want)
{
	if (!ak_deny_code_armed(flags, cgid))
		return 0;
	__u64 h = ak_fnv1a(buf, AK_PATH_MAX);
	__u32 *t = bpf_map_lookup_elem(&ak_taint_files, &h);
	if (t && (*t & want))
		return 1;
	return ak_ino_tainted(ino, want);
}

// ak_is_anon_file: whether a resolved path names an anonymous in-memory file
// (memfd_create). Such a file is created by alloc_file_pseudo() and never
// traverses security_file_open, so no write of the session's can set a provenance
// key on it, and neither key is consulted at exec. It is the one alias a session
// can produce that carries no label at all, so it is refused on the absence of a
// path rather than on the presence of one.
static __always_inline int ak_is_anon_file(const char *b)
{
	return b[0] == '/' && b[1] == 'm' && b[2] == 'e' && b[3] == 'm' &&
	       b[4] == 'f' && b[5] == 'd' && b[6] == ':';
}

// ak_taint_write marks a write-opened file as agent-written, synchronously
// in-kernel (no userspace round-trip). Gated on the session's deny-tainted-code
// flag (fork-propagated across the agent's cgroup tree). Also sets the code bit
// if the inode already carries an execute permission.
static __always_inline void ak_taint_write(const char *buf, __u32 flags, __u64 cgid, struct file *file)
{
	if (!ak_deny_code_armed(flags, cgid))
		return;
	__u64 h = ak_fnv1a(buf, AK_PATH_MAX);
	__u32 tv = AK_TAINT_WRITTEN;
	// Direct dereference (not BPF_CORE_READ) keeps the inode a verifier-trusted
	// pointer, which bpf_inode_storage_get requires; CO-RE still relocates the field.
	struct inode *ino = file->f_inode;
	umode_t im = ino ? BPF_CORE_READ(ino, i_mode) : 0;
	if (im & 0111)
		tv |= AK_TAINT_CODE;
	__u32 *ex = bpf_map_lookup_elem(&ak_taint_files, &h);
	if (ex)
		tv |= *ex;
	if (bpf_map_update_elem(&ak_taint_files, &h, &tv, BPF_ANY))
		ak_bump_err(AK_ERR_TAINT_STORE); // path key unavailable; inode key below still carries it

	// Inode-keyed taint: robust to hard link / rename / mount-ns alias and LRU eviction.
	if (ino) {
		__u32 *iv = bpf_inode_storage_get(&ak_taint_inode, ino, 0,
						  BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (iv)
			*iv |= tv;
	}
}

SEC("lsm/file_open")
int BPF_PROG(ak_lsm_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret; // respect an earlier LSM denial

	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	if (!(flags & AK_SESS_MONITOR))
		return 0;

	// If the kernel yields no path at all, no rule, taint, or sensitive key can be
	// formed for this open, so an enforce-mode session is refused rather than let
	// through unmediated.
	char *buf = ak_path_resolve(&file->f_path);
	if (!buf) {
		ak_emit_unresolved(cgid, AK_PSEUDO_LSM_FILE, AK_CAT_FILE);
		return (flags & AK_SESS_ENFORCE) ? -1 : 0;
	}

	// Visibility event for the opened path.
	ak_emit_kstr(cgid, AK_PSEUDO_LSM_FILE, AK_CAT_FILE, 0, buf);

	if (!(flags & AK_SESS_ENFORCE))
		return 0;

	if (ak_forbidden(buf, AK_OP_OPEN))
		return -1; // -EPERM

	// Write opens: block writes to protected paths (e.g. AgentKnox's own config /
	// policy dir), then taint the file in-kernel (race-free provenance). Read opens:
	// block if it is agent-written code (interpreter reading a script to run it).
	unsigned int fmode = BPF_CORE_READ(file, f_mode);
	if (fmode & 0x2 /* FMODE_WRITE */) {
		if (ak_forbidden(buf, AK_OP_WRITE))
			return -1; // -EPERM: write-open of a protected path
		ak_taint_write(buf, flags, cgid, file);
	} else {
		if (ak_deny_taint(buf, file->f_inode, flags, cgid, AK_TAINT_CODE))
			return -1; // agent-written code, read-for-exec blocked (interpreter case)
		// Sensitive-source read: arms deny-egress on this pid synchronously in-kernel
		// (a read-open of a daemon-marked secret bars all subsequent egress). Keyed on
		// the absolute-path hash (matches userspace HashString); the LSM file_open hook
		// also fires for io_uring opens, unlike syscall tracepoints.
		__u64 sh = ak_fnv1a(buf, AK_PATH_MAX);
		__u32 *sv = bpf_map_lookup_elem(&ak_sensitive_files, &sh);
		if (sv && *sv) {
			__u32 tgid = ak_tgid();
			__u32 nf = flags | AK_SESS_DENY_EGRESS;
			long e1 = bpf_map_update_elem(&ak_session_pids, &tgid, &nf, BPF_ANY);
			// Cgroup-scoped deny-egress: io_uring read+POST runs on io-wq kernel worker
			// threads with a different tgid than the submitter, so a per-pid flag alone
			// may miss the POST; the per-cgroup posture covers it instead.
			__u32 *pp = bpf_map_lookup_elem(&ak_posture, &cgid);
			__u32 pv = (pp ? *pp : 0) | AK_POSTURE_DENY_EGRESS;
			long e2 = bpf_map_update_elem(&ak_posture, &cgid, &pv, BPF_ANY);
			// Neither arm could be recorded (map exhaustion): the read is what arms
			// egress, so allowing it here would hand the session an unguarded secret.
			if (e1 && e2) {
				ak_bump_err(AK_ERR_ARM_EGRESS);
				return -1;
			}
		}
	}

	return 0;
}

// Deny execution of forbidden binaries/scripts. Policy defines "the tool may not
// run X"; the absolute path of the program being exec'd is matched pre-exec.
SEC("lsm/bprm_check_security")
int BPF_PROG(ak_lsm_bprm, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;
	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	int armed = ak_flags_get() & AK_FLAG_PERSIST_ARMED;

	// In-kernel agent arming: tag recognized agent binary into ak_session_pids at
	// exec (pre-userspace). Cheap path: bprm->filename read, basename hash, one
	// map lookup.
	if (!(flags & AK_SESS_MONITOR)) {
		const char *fn = BPF_CORE_READ(bprm, filename);
		if (fn) {
			char nb[AK_MAX_STR] = {};
			long fl = bpf_probe_read_kernel_str(nb, sizeof(nb), fn);
			if (fl > 0) {
				__u64 sh = ak_fnv1a_basename(nb);
				__u32 *sf = bpf_map_lookup_elem(&ak_agent_sigs, &sh);
				if (sf) {
					__u32 tgid = ak_tgid();
					__u32 sv = *sf;
					if (bpf_map_update_elem(&ak_session_pids, &tgid, &sv, BPF_ANY)) {
						// The membership write was rejected (the per-pid map is
						// full). Nothing downstream can then see this process as a
						// session member, so its opens, execs, and connects would
						// all run unmediated. An enforce-mode agent is refused at
						// exec instead of started outside its own envelope; a
						// monitor-only agent still starts, since refusing an exec
						// is not a monitor session's contract. Both are reported.
						ak_bump_err(AK_ERR_ARM_SESSION);
						ak_emit_arm_fault(cgid);
						if (sv & AK_SESS_ENFORCE)
							return -1; // -EPERM: no unenforced agent start
					} else {
						flags = sv; // this exec is now an armed session member
					}
				}
			}
		}
	}

	// Inherit-at-exec: if this exec is not itself a signature but its parent is
	// already an armed session member, arm it here, before exec returns. Covers a
	// clone/vfork/posix_spawn variant that does not fire sched_process_fork (e.g.
	// a sandboxed shell/worker spawn).
	if (!(flags & AK_SESS_MONITOR)) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		__u32 ptgid = BPF_CORE_READ(task, real_parent, tgid);
		__u32 *pf = bpf_map_lookup_elem(&ak_session_pids, &ptgid);
		if (pf) {
			__u32 tgid = ak_tgid();
			__u32 sv = *pf;
			if (bpf_map_update_elem(&ak_session_pids, &tgid, &sv, BPF_ANY)) {
				// Same fault on the inherit path: a child of an armed member that
				// cannot be recorded escapes every later hook. Under an enforce-mode
				// parent the child is refused rather than run as an unmediated
				// member of the session.
				ak_bump_err(AK_ERR_ARM_SESSION);
				ak_emit_arm_fault(cgid);
				if (sv & AK_SESS_ENFORCE)
					return -1; // -EPERM
			} else {
				flags = sv;
			}
		}
	}

	// Skip if not a session member and persistence detection is disarmed: avoids
	// d_path on every unrelated exec on the host.
	if (!(flags & AK_SESS_MONITOR) && !armed)
		return 0;

	// An unresolvable path leaves the exec unmatchable against every rule below, so
	// an enforce-mode session is refused; a non-member reached here only by the
	// global persistence sweep and carries no enforce flag.
	char *buf = ak_path_resolve(&bprm->file->f_path);
	if (!buf) {
		ak_emit_unresolved(cgid, AK_PSEUDO_LSM_EXEC, AK_CAT_PROCESS);
		return (flags & AK_SESS_ENFORCE) ? -1 : 0;
	}

	// Global persistence-artifact detection (observe/attribution only): surfaces
	// execution of an agent-registered artifact (cron/systemd/hook) by an
	// out-of-tree process that reparented away from the session. Blocking, if
	// wanted, is a normal policy rule, not a special case here.
	if (armed) {
		__u64 h = ak_fnv1a(buf, AK_PATH_MAX);
		__u32 *t = bpf_map_lookup_elem(&ak_taint_files, &h);
		if (t && (*t & AK_TAINT_PERSIST))
			ak_emit_kstr(cgid, AK_PSEUDO_PERSIST_EXEC, AK_CAT_PROCESS, 0, buf);
	}

	if (!(flags & AK_SESS_MONITOR))
		return 0;

	ak_emit_kstr(cgid, AK_PSEUDO_LSM_EXEC, AK_CAT_PROCESS, 0, buf);

	if (!(flags & AK_SESS_ENFORCE))
		return 0;

	if (ak_forbidden(buf, AK_OP_EXEC))
		return -1;
	if (ak_deny_taint(buf, bprm->file->f_inode, flags, cgid, AK_TAINT_WRITTEN))
		return -1; // any agent-written file: direct exec blocked (content-agnostic)
	// execveat(memfd, "", AT_EMPTY_PATH): an in-memory image the session wrote
	// without ever opening a file. Refused under the same provenance policy.
	if (ak_deny_code_armed(flags, cgid) && ak_is_anon_file(buf))
		return -1;
	// Interpreter-script disguise (`python data.txt`, incl. relative paths) is
	// resolved in userspace and enforced via Kill: doing the argv+cwd resolution
	// here blows the verifier's 1M-instruction budget.
	return 0;
}

// Shared helper for path-based mutation hooks that already have a struct path*
// pointing at the target file (chmod/chown).
static __always_inline int ak_enforce_path(const struct path *path, __u32 op)
{
	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	if (!(flags & AK_SESS_ENFORCE))
		return 0;
	char *buf = ak_path_resolve((struct path *)path);
	if (!buf) {
		// The target cannot be matched against any rule, and the caller is an
		// enforce-mode session member, so the mutation is refused and recorded.
		ak_emit_unresolved(cgid, AK_PSEUDO_LSM_FILE, AK_CAT_FILE);
		return -1;
	}
	if (ak_forbidden(buf, op))
		return -1;
	return 0;
}

// Shared helper for hooks that reference a target via parent dir + dentry
// (unlink/rmdir/rename).
static __always_inline int ak_enforce_dentry(const struct path *dir,
					     struct dentry *dentry, __u32 op)
{
	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	if (!(flags & AK_SESS_ENFORCE))
		return 0;
	char nbuf[AK_NAME_MAX] = {};
	char *dbuf = ak_path_resolve((struct path *)dir);
	if (!dbuf) {
		ak_emit_unresolved(cgid, AK_PSEUDO_LSM_FILE, AK_CAT_FILE);
		return -1;
	}
	struct qstr q = BPF_CORE_READ(dentry, d_name);
	bpf_probe_read_kernel_str(nbuf, sizeof(nbuf), q.name);
	if (ak_forbidden_split(dbuf, nbuf, op))
		return -1;
	return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(ak_lsm_path_chmod, const struct path *path, umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	return ak_enforce_path(path, AK_OP_CHMOD);
}

SEC("lsm/path_chown")
int BPF_PROG(ak_lsm_path_chown, const struct path *path, void *uid, void *gid, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	return ak_enforce_path(path, AK_OP_CHOWN);
}

// truncate(2)/ftruncate(2) reach a file's contents without opening it, so an
// enforce-mode member could zero a write-protected file (the policy directory's
// documents, the audit log) past the write-open gate. security_path_truncate is
// the pre-operation hook for both, and the op checked is WRITE, so a path already
// write-protected by policy or by self-protection needs no extra rule.
SEC("lsm/path_truncate")
int BPF_PROG(ak_lsm_path_truncate, const struct path *path, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	return ak_enforce_path(path, AK_OP_WRITE);
}

SEC("lsm/path_unlink")
int BPF_PROG(ak_lsm_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	return ak_enforce_dentry(dir, dentry, AK_OP_DELETE);
}

SEC("lsm/path_rmdir")
int BPF_PROG(ak_lsm_path_rmdir, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	return ak_enforce_dentry(dir, dentry, AK_OP_DELETE);
}

SEC("lsm/path_rename")
int BPF_PROG(ak_lsm_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags2, int ret)
{
	if (ret != 0)
		return ret;
	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	if (!(flags & AK_SESS_MONITOR))
		return 0;

	// Move provenance taint across rename: taint keys on the absolute path, so
	// renaming an agent-written file (e.g. write-to-temp-then-rename) would
	// otherwise shed the taint. Copies the old path's taint to the new path,
	// gated on the session's deny-tainted-code flag.
	if (ak_deny_code_armed(flags, cgid)) {
		// Reuse ONE scratch slot for old then new: hash the old path, look up its
		// taint, then resolve the new path over the same buffer and propagate.
		char nb[AK_NAME_MAX] = {};
		char *db = ak_path_resolve((struct path *)old_dir);
		if (db) {
			struct qstr oq = BPF_CORE_READ(old_dentry, d_name);
			bpf_probe_read_kernel_str(nb, sizeof(nb), oq.name);
			__u64 oh = ak_fnv1a_split(db, nb);
			__u32 *t = bpf_map_lookup_elem(&ak_taint_files, &oh);
			if (t) {
				__u32 tv = *t;
				db = ak_path_resolve((struct path *)new_dir);
				if (db) {
					struct qstr nq = BPF_CORE_READ(new_dentry, d_name);
					bpf_probe_read_kernel_str(nb, sizeof(nb), nq.name);
					__u64 nh = ak_fnv1a_split(db, nb);
					if (bpf_map_update_elem(&ak_taint_files, &nh, &tv, BPF_ANY))
						ak_bump_err(AK_ERR_TAINT_STORE);
				}
			}
		}
	}

	if (!(flags & AK_SESS_ENFORCE))
		return 0;
	return ak_enforce_dentry(old_dir, old_dentry, AK_OP_RENAME);
}

// Network egress pre-block. Denies connect() before it happens based on:
//   (a) per-session deny-all-egress posture (set when a session is tainted or
//       policy escalates: pre-blocks semantic-derived verdicts), and
//   (b) an LPM trie of denied IPv4 prefixes.
SEC("lsm/socket_connect")
int BPF_PROG(ak_lsm_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret != 0)
		return ret;

	__u64 cgid = 0;
	__u32 flags = ak_session_flags(&cgid);
	if (!(flags & AK_SESS_MONITOR))
		return 0;

	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), address); // sa_family is first
	if (family != 2 /* AF_INET */ && family != 10 /* AF_INET6 */)
		return 0;

	if (!(flags & AK_SESS_ENFORCE))
		return 0;

	// Destination port (sin_port / sin6_port both at offset 2, network byte order).
	// DNS (port 53) is exempt from the blanket deny-egress below so a tainted session
	// can still resolve names (the data-carrying connect is still refused); this avoids
	// a resolver retry storm and keeps the block on data egress, not name resolution.
	__u16 nport = 0;
	bpf_probe_read_kernel(&nport, sizeof(nport), (char *)address + 2);
	__u16 dport = (__u16)((nport >> 8) | (nport << 8));

	// (a0) session-flag deny-egress: fork-propagated to the exfil child even when it
	// lives in a different cgroup than the one the per-cgroup posture below was armed on.
	if ((flags & AK_SESS_DENY_EGRESS) && dport != 53)
		return -1; // -EPERM

	// (a) deny-all-egress posture for this session's cgroup: both families.
	__u32 *posture = bpf_map_lookup_elem(&ak_posture, &cgid);
	if (posture && (*posture & AK_POSTURE_DENY_EGRESS) && dport != 53)
		return -1; // -EPERM

	// (b) denied-prefix match, per family.
	if (family == 2 /* AF_INET */) {
		struct sockaddr_in sin = {};
		bpf_probe_read_kernel(&sin, sizeof(sin), address);
		struct ak_lpm_key key = {};
		key.prefixlen = 32;
		__builtin_memcpy(key.addr, &sin.sin_addr, 4);
		__u32 *act = bpf_map_lookup_elem(&ak_enforce_net, &key);
		if (act && *act)
			return -1;
	} else {
		struct sockaddr_in6 sin6 = {};
		bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
		struct ak_lpm_key6 key6 = {};
		key6.prefixlen = 128;
		__builtin_memcpy(key6.addr, &sin6.sin6_addr, 16);
		__u32 *act = bpf_map_lookup_elem(&ak_enforce_net6, &key6);
		if (act && *act)
			return -1;
	}

	return 0;
}

// Pre-operation DB query block: the DB-write capture (ak_db_sendto) marks the pid
// in ak_db_deny_pending when the outbound COM_QUERY names a policy-denied table.
// Because that tracepoint fires at syscall entry, ahead of this LSM hook in the
// same sendto(), the mark is present here and the send is refused with -EPERM
// before the query reaches the server. Consumed once (deleted) per send.
SEC("lsm/socket_sendmsg")
int BPF_PROG(ak_lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_flags_get() & AK_FLAG_DB_BLOCK_ARMED))
		return 0;
	__u32 tgid = ak_tgid();
	if (!bpf_map_lookup_elem(&ak_db_deny_pending, &tgid))
		return 0;
	bpf_map_delete_elem(&ak_db_deny_pending, &tgid);
	if (!(ak_session_flags(NULL) & AK_SESS_ENFORCE))
		return 0;
	return -1; // -EPERM
}

// Self-protection: deny an enforce-mode session member from signaling the
// AgentKnox daemon. sig==0 (permission probe) is allowed.
SEC("lsm/task_kill")
int BPF_PROG(ak_lsm_task_kill, struct task_struct *p, void *info, int sig,
	     void *cred, int ret)
{
	if (ret != 0)
		return ret;
	if (sig == 0)
		return 0;
	if (!(ak_session_flags(NULL) & AK_SESS_ENFORCE))
		return 0;
	__u32 target = BPF_CORE_READ(p, tgid);
	if (bpf_map_lookup_elem(&ak_self, &target))
		return -1; // -EPERM
	return 0;
}

// Self-protection: deny an enforce-mode session member from ptracing the
// AgentKnox daemon (anti-injection / anti-inspection of the monitor).
SEC("lsm/ptrace_access_check")
int BPF_PROG(ak_lsm_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	if (ret != 0)
		return ret;
	if (!(ak_session_flags(NULL) & AK_SESS_ENFORCE))
		return 0;
	__u32 target = BPF_CORE_READ(child, tgid);
	if (bpf_map_lookup_elem(&ak_self, &target))
		return -1;
	return 0;
}
