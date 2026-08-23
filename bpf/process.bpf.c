// SPDX-License-Identifier: GPL-2.0
// process.bpf.c — process execution and exit. exec/exit are captured GLOBALLY
// (self-exclusion only) so userspace can DETECT new agent processes before their
// cgroup is registered; file/network programs remain session-gated for volume.
#pragma once

SEC("tp/syscalls/sys_enter_execve")
int ak_execve(struct trace_event_raw_sys_enter *ctx)
{
	if (ak_is_self())
		return 0;
	__u64 cgid = bpf_get_current_cgroup_id();
	const char *filename = (const char *)ctx->args[0];
	ak_emit(cgid, ctx->id, AK_CAT_PROCESS, 0, filename);

	// In-kernel argv-based agent arming: an interpreter-launched agent (`node
	// /usr/bin/gemini`, `python -m agent`) has a generic exec filename that the
	// bprm signature match cannot recognize. Matching argv basenames against the
	// signature map at execve entry (still the caller's mm, so argv is readable)
	// arms the tgid so the post-exec process is enforced from its first
	// instruction. Idempotent.
	__u32 tgid = ak_tgid();
	if (bpf_map_lookup_elem(&ak_session_pids, &tgid))
		return 0;
	const char *const *argv = (const char *const *)ctx->args[1];
	if (!argv)
		return 0;
	// The agent can sit past argv[1]: an interpreter re-exec carries it as a later
	// arg (Node's heap-tuned respawn `node --max-old-space-size=<N>
	// /usr/bin/gemini` puts it at argv[2]). Bounded at 4 entries to keep the probe
	// cheap and the loop verifiable.
	char nb[AK_MAX_STR] = {};
#pragma unroll
	for (int i = 0; i < 4; i++) {
		const char *ap = NULL;
		if (bpf_probe_read_user(&ap, sizeof(ap), &argv[i]) != 0 || !ap)
			continue;
		if (bpf_probe_read_user_str(nb, sizeof(nb), ap) <= 0)
			continue;
		__u64 sh = ak_fnv1a_basename(nb);
		__u32 *sf = bpf_map_lookup_elem(&ak_agent_sigs, &sh);
		if (sf) {
			__u32 sv = *sf;
			// A rejected write (per-pid map full) leaves this process unarmed. A
			// syscall tracepoint cannot refuse the exec, so the fault is recorded;
			// the bprm LSM hook, which runs later in the same execve and can refuse,
			// is what fails an enforce-mode session closed.
			if (bpf_map_update_elem(&ak_session_pids, &tgid, &sv, BPF_ANY))
				ak_bump_err(AK_ERR_ARM_SESSION);
			return 0;
		}
	}

	// Reparent-worker arming: a worker the agent spawns that is not itself a
	// signature (e.g. a `bash`/`sh` for write+exec or file read) is missed by the
	// argv match above, and a sandbox reparent to init before its children exec
	// leaves bprm parent-arming with no armed parent to find. Two paths: (a) if
	// still in the agent's armed session cgroup at execve, pin those flags to its
	// pid so the tag survives reparent + cgroup move; (b) else inherit from
	// real_parent when it is an armed member.
	__u32 *cf = bpf_map_lookup_elem(&ak_sessions, &cgid);
	if (cf) {
		__u32 sv = *cf;
		if (bpf_map_update_elem(&ak_session_pids, &tgid, &sv, BPF_ANY))
			ak_bump_err(AK_ERR_ARM_SESSION);
		return 0;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 ptgid = BPF_CORE_READ(task, real_parent, tgid);
	__u32 *pf = bpf_map_lookup_elem(&ak_session_pids, &ptgid);
	if (pf) {
		__u32 sv = *pf;
		if (bpf_map_update_elem(&ak_session_pids, &tgid, &sv, BPF_ANY))
			ak_bump_err(AK_ERR_ARM_SESSION);
	}
	return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int ak_execveat(struct trace_event_raw_sys_enter *ctx)
{
	if (ak_is_self())
		return 0;
	__u64 cgid = bpf_get_current_cgroup_id();
	const char *filename = (const char *)ctx->args[1];
	ak_emit(cgid, ctx->id, AK_CAT_PROCESS, 0, filename);
	return 0;
}

// ak_proc_fork propagates session membership to a child at birth, in-kernel, so
// a double-fork / setsid / daemonize that reparents to init cannot shed the tag
// (no exec or userspace round-trip needed). Runs in the forking parent's
// context.
SEC("tp/sched/sched_process_fork")
int ak_proc_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	if (ak_is_self())
		return 0;
	__u32 ptgid = ak_tgid();
	__u32 *pf = bpf_map_lookup_elem(&ak_session_pids, &ptgid);
	if (!pf)
		return 0; // parent not a session member
	__u32 child = (__u32)ctx->child_pid;
	__u32 flags = *pf;
	// An unrecorded child inherits nothing and runs outside the session; a
	// tracepoint cannot refuse the fork, so the fault is counted and the userspace
	// re-arm sweep is what recovers the child.
	if (bpf_map_update_elem(&ak_session_pids, &child, &flags, BPF_ANY))
		ak_bump_err(AK_ERR_ARM_SESSION);
	return 0;
}

// ak_new_task arms a new task at birth via kprobe on wake_up_new_task, which the
// kernel calls for every newly-created task regardless of clone flavor (fork,
// vfork, clone3, posix_spawn's CLONE_VM|CLONE_VFORK); sched_process_fork misses
// some of these. It runs in the forking parent's context, so it also covers a
// launcher that exits right after spawning, whose session-pids entry would
// otherwise be gone before the child's execve fallback runs.
SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(ak_new_task, struct task_struct *p)
{
	if (ak_is_self())
		return 0;
	__u32 ptgid = ak_tgid(); // current = the forking parent
	__u32 *pf = bpf_map_lookup_elem(&ak_session_pids, &ptgid);
	if (!pf)
		return 0;
	__u32 ctgid = BPF_CORE_READ(p, tgid);
	if (ctgid == ptgid)
		return 0; // a new thread of an already-armed process; nothing to add
	__u32 flags = *pf;
	if (bpf_map_update_elem(&ak_session_pids, &ctgid, &flags, BPF_ANY))
		ak_bump_err(AK_ERR_ARM_SESSION);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int ak_proc_exit(void *ctx)
{
	if (ak_is_self())
		return 0;
	// Only emit exits for registered sessions (keeps volume down).
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, AK_PSEUDO_SCHED_EXIT, AK_CAT_PROCESS, 0, NULL);
	// Bound ak_session_pids. sched_process_fork also fires for thread creation, and
	// the hook there keys the new task's pid (a tid for a thread) into this
	// tgid-keyed map. Deleting only on leader exit therefore leaked one entry per
	// thread the session ever created: the map is a plain HASH, so once it fills,
	// inserts fail and new children go unarmed, and a leaked tid can later collide
	// with an unrelated process's tgid and hand it the session's flags. Delete the
	// exiting task's own key, which balances both the fork and the thread case.
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 self = (__u32)pt;
	bpf_map_delete_elem(&ak_session_pids, &self);
	return 0;
}
