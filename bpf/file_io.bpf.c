// SPDX-License-Identifier: GPL-2.0
// file_io.bpf.c — file open (path visibility). Read/write intent summarized
// from open flags.
#pragma once

SEC("tp/syscalls/sys_enter_openat")
int ak_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	const char *pathname = (const char *)ctx->args[1];
	__s64 flags = (__s64)ctx->args[2];
	ak_emit(cgid, ctx->id, AK_CAT_FILE, flags, pathname);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int ak_openat2(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	const char *pathname = (const char *)ctx->args[1];
	ak_emit(cgid, ctx->id, AK_CAT_FILE, 0, pathname);
	return 0;
}
