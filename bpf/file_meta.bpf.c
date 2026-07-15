// SPDX-License-Identifier: GPL-2.0
// file_meta.bpf.c — file mutation operations agents perform (create/delete/
// rename/permission changes). Session-gated; emits the target path.
#pragma once

SEC("tp/syscalls/sys_enter_unlinkat")
int ak_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int ak_unlink(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[0]);
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int ak_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int ak_rename(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[0]);
	return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int ak_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int ak_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_fchownat")
int ak_fchownat(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, (const char *)ctx->args[1]);
	return 0;
}
