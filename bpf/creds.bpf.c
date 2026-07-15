// SPDX-License-Identifier: GPL-2.0
// creds.bpf.c — privilege-escalation-relevant operations (kill, ptrace, setuid).
// Session-gated. Agents rarely do these; when they do it is security-relevant.
#pragma once

SEC("tp/syscalls/sys_enter_ptrace")
int ak_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	// retval field carries the ptrace request; resource carries target pid.
	ak_emit(cgid, ctx->id, AK_CAT_PROCESS, (__s64)ctx->args[0], NULL);
	return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int ak_kill(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_PROCESS, (__s64)ctx->args[1], NULL);
	return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int ak_setuid(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_CAP, (__s64)ctx->args[0], NULL);
	return 0;
}

SEC("tp/syscalls/sys_enter_setreuid")
int ak_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_CAP, (__s64)ctx->args[1], NULL);
	return 0;
}

// io_uring SQE submission: async file/net ops bypass sys_enter_* tracepoints;
// surfaced here with the opcode (LSM hooks still catch the effects).
SEC("tp/io_uring/io_uring_submit_req")
int ak_io_uring_submit(struct trace_event_raw_io_uring_submit_req *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, AK_PSEUDO_IO_URING, AK_CAT_PROCESS, (__s64)ctx->opcode, NULL);
	return 0;
}
