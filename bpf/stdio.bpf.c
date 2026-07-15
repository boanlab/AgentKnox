// SPDX-License-Identifier: GPL-2.0
// stdio.bpf.c — stdio-MCP capture. Local (stdio-transport) MCP servers exchange
// JSON-RPC over pipes, which never cross the TLS boundary the uprobes watch.
// These hooks lift the plaintext at the pipe boundary for fds userspace has
// registered in ak_mcp_fds, emitting into the SAME semantic ring as TLS chunks
// so the existing parser reassembles JSON-RPC unchanged. Capture is gated on the
// per-(tgid,fd) map, so unrelated read/write traffic is never touched.
#pragma once

static __always_inline int ak_mcp_fd(__u32 tgid, __u64 fd)
{
	__u64 key = ((__u64)tgid << 32) | (fd & 0xffffffff);
	return bpf_map_lookup_elem(&ak_mcp_fds, &key) != NULL;
}

static __always_inline int ak_db_fd(__u32 tgid, __u64 fd)
{
	__u64 key = ((__u64)tgid << 32) | (fd & 0xffffffff);
	return bpf_map_lookup_elem(&ak_db_fds, &key) != NULL;
}

#define AK_DB_SCAN 64 // bytes of SQL scanned for a denied table name
#define AK_DB_PAT  16 // max denied table-name length matched in-kernel

// ak_sql_ident reports whether c (lowercased) is a SQL identifier character, so a
// table reference can be delimited by a word boundary on either side.
static __always_inline int ak_sql_ident(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

// ak_sql_delim reports whether c can immediately precede a table reference. These are
// the characters MySQL/MariaDB accepts there: the whitespace that separates keywords
// from operands, the backtick that quotes an identifier, the dot of a schema-qualified
// name, an opening parenthesis, and the comma of a table list. Everything else (a
// quote, an identifier character) leaves the following token inside a literal or in
// the middle of a longer name, so it is not a table reference. Kept a flat compare
// chain over one already-loaded byte: no loop, no lookup, no extra verifier state.
static __always_inline int ak_sql_delim(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '`' ||
	       c == '.' || c == '(' || c == ',';
}

// ak_db_match_slot reports whether the (already-lowercased) SQL names the denied
// table in slot `slot` as a delimiter-anchored token. Anchoring on a preceding SQL
// delimiter (a table reference is `... FROM users`, `FROM\tusers`, "FROM `users`",
// `FROM db.users`, `FROM (users)`, `FROM p, users`, whereas a literal is `'users'`)
// rejects the name inside a quoted string, which a raw substring would over-block.
// The scan runs as far as the denied name itself allows: the last offset at which a
// name of `plen` bytes still fits inside the lowercased window, so a short name is
// matched further into the statement than a long one. Fully unrolled to constant
// offsets so it verifies with a small stack. Residual (narrowed by the userspace
// parser where the statement is available): a column/alias whose name equals the
// denied table, or a longer identifier with the denied name as its prefix.
static __noinline int ak_db_match_slot(const char *sql, __u32 slot)
{
	__u32 key = slot;
	struct ak_db_pat *p = bpf_map_lookup_elem(&ak_db_deny_tables, &key);
	if (!p)
		return 0;
	__u32 plen = p->len;
	if (plen == 0 || plen > AK_DB_PAT)
		return 0;
#pragma unroll
	for (int s = 6; s <= AK_DB_SCAN - 2; s++) {
		if (!ak_sql_delim(sql[s - 1]))
			continue; // token must open a table reference, not sit in a literal
		if (s + plen > AK_DB_SCAN)
			continue; // the name would run past the lowercased window
		__u32 miss = 0;
#pragma unroll
		for (int j = 0; j < AK_DB_PAT; j++) {
			if (s + j >= AK_DB_SCAN)
				break; // constant-folded; emits no read past the window
			__u32 active = ((__u32)j < plen);
			miss |= active * (__u32)((__u8)(sql[s + j] ^ p->pat[j]));
		}
		if (!miss)
			return 1;
	}
	return 0;
}

// ak_mongo_match_slot reports whether a MongoDB OP_MSG command targets the denied
// collection in slot `slot`. The wire is a 16-byte header (opCode 2013 at [12:16],
// little-endian DD 07 00 00), flagBits [16:20], a body section (kind 0x00 at [20]),
// then a BSON command whose first element is a string (the verb, e.g. find/aggregate)
// whose VALUE is the collection, encoded [len:4 LE][name][0x00]. Anchoring on that
// length prefix plus the first-element string type identifies the collection itself,
// not a string value elsewhere in the document.
static __noinline int ak_mongo_match_slot(int len, __u32 slot)
{
	__u32 z = 0;
	struct ak_db_buf *sb = bpf_map_lookup_elem(&ak_db_scratch, &z);
	if (!sb)
		return 0;
	const char *b = sb->b; // fresh map-value pointer with known bounds
	__u32 key = slot;
	struct ak_db_pat *p = bpf_map_lookup_elem(&ak_db_deny_tables, &key);
	if (!p)
		return 0;
	__u32 plen = p->len;
	if (plen == 0 || plen > AK_DB_PAT)
		return 0;
	if (b[20] != 0x00 || b[25] != 0x02)
		return 0; // not a body section whose first command element is a string
#pragma unroll
	for (int cs = 30; cs <= 40; cs++) {
		if (cs + 4 + AK_DB_PAT + 1 > len)
			continue;
		if ((__u8)b[cs] != (__u8)(plen + 1) || b[cs + 1] || b[cs + 2] || b[cs + 3])
			continue; // BSON string length must be collection length + 1
		__u32 miss = 0;
#pragma unroll
		for (int j = 0; j <= AK_DB_PAT; j++) {
			char c = b[cs + 4 + j];
			__u32 active = ((__u32)j < plen);
			__u32 term = ((__u32)j == plen);
			miss |= active * (__u32)((__u8)(c ^ p->pat[j]));
			miss |= term * (__u32)((__u8)c); // collection cstring terminator
		}
		if (!miss)
			return 1;
	}
	return 0;
}

// ak_db_query_check inspects one outbound DB payload and marks the pid in
// ak_db_deny_pending when it targets a policy-denied table/collection, so the
// socket_sendmsg LSM hook refuses this same send with -EPERM (pre-operation block).
// It dispatches by wire framing: MongoDB OP_MSG (opCode 2013) first, else a
// MySQL/MariaDB COM_QUERY ([len:3][seq:1][0x03][plaintext SQL]). Case-insensitive:
// the payload is lowercased once and the patterns are stored lowercased by userspace.
static __noinline void ak_db_query_check(__u32 tgid, const char *buf, int len)
{
	if (len < 6)
		return;
	__u32 z = 0;
	struct ak_db_buf *s = bpf_map_lookup_elem(&ak_db_scratch, &z);
	if (!s)
		return;
	char *sql = s->b;
	// Read only the bytes the payload actually holds. A fixed full-scratch read
	// faults in its entirety when a short query ends near a page boundary, and the
	// send would then pass unchecked, so a denied query could be smuggled by its
	// placement alone. Zeroed first, so a short payload leaves no bytes of the
	// previous one on this CPU.
	__u32 n = (__u32)len;
	if (n > AK_DB_SCAN)
		n = AK_DB_SCAN;
	__builtin_memset(sql, 0, AK_DB_SCAN);
	if (bpf_probe_read_user(sql, n, buf) != 0) {
		ak_bump_err(AK_ERR_DB_READ); // unreadable payload, counted rather than silent
		return;
	}
#pragma unroll
	for (int k = 0; k < AK_DB_SCAN; k++) {
		char c = sql[k];
		sql[k] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
	}
	int hit = 0;
	if ((__u8)sql[12] == 0xDD && (__u8)sql[13] == 0x07 && !sql[14] && !sql[15]) {
		hit = ak_mongo_match_slot(len, 0) || ak_mongo_match_slot(len, 1) ||
		      ak_mongo_match_slot(len, 2) || ak_mongo_match_slot(len, 3);
	} else if (sql[4] == 0x03) {
		hit = ak_db_match_slot(sql, 0) || ak_db_match_slot(sql, 1) ||
		      ak_db_match_slot(sql, 2) || ak_db_match_slot(sql, 3);
	}
	if (hit) {
		__u8 one = 1;
		bpf_map_update_elem(&ak_db_deny_pending, &tgid, &one, BPF_ANY);
	}
}

// write(fd, buf, count): captured for a registered stdio-MCP pipe (JSON-RPC) or a
// registered DB socket (plaintext wire-protocol query). Both emit into the semantic
// ring; userspace routes DB pids to the wire parser and the rest to the JSON parser.
SEC("tp/syscalls/sys_enter_write")
int ak_stdio_write(struct trace_event_raw_sys_enter *ctx)
{
	// Armed flags (cheap array lookup) FIRST: this hook fires on every write() on the
	// host, so when neither stdio-MCP nor DB capture is armed it returns immediately,
	// skipping the per-fd hash lookups entirely.
	__u32 fl = ak_flags_get();
	if (!(fl & (AK_FLAG_MCP_ARMED | AK_FLAG_DB_ARMED)))
		return 0;
	if (ak_is_self())
		return 0;
	__u32 tgid = ak_tgid();
	__u64 fd = ctx->args[0];
	int is_mcp = (fl & AK_FLAG_MCP_ARMED) && ak_mcp_fd(tgid, fd);
	int is_db = (fl & AK_FLAG_DB_ARMED) && ak_db_fd(tgid, fd);
	if (!is_mcp && !is_db)
		return 0;
	ak_emit_tls(bpf_get_current_cgroup_id(), 0, (const char *)ctx->args[1],
		    (int)ctx->args[2], 0);
	if (is_db && (fl & AK_FLAG_DB_BLOCK_ARMED))
		ak_db_query_check(tgid, (const char *)ctx->args[1], (int)ctx->args[2]);
	return 0;
}

// sendto(fd, buf, len, flags, dest, addrlen) on a registered DB socket: the send()
// path a DB client library (e.g. libpq) uses on its connected socket, which the
// write hook above does not see. Same emit into the semantic ring.
SEC("tp/syscalls/sys_enter_sendto")
int ak_db_sendto(struct trace_event_raw_sys_enter *ctx)
{
	if (!(ak_flags_get() & AK_FLAG_DB_ARMED))
		return 0;
	if (ak_is_self())
		return 0;
	__u32 tgid = ak_tgid();
	if (!ak_db_fd(tgid, ctx->args[0]))
		return 0;
	ak_emit_tls(bpf_get_current_cgroup_id(), 0, (const char *)ctx->args[1],
		    (int)ctx->args[2], 0);
	if (ak_flags_get() & AK_FLAG_DB_BLOCK_ARMED)
		ak_db_query_check(tgid, (const char *)ctx->args[1], (int)ctx->args[2]);
	return 0;
}

// read(fd, buf, count): stash the buffer at entry; emit at exit with the real
// byte count. Only for registered pipe fds.
SEC("tp/syscalls/sys_enter_read")
int ak_stdio_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!(ak_flags_get() & AK_FLAG_MCP_ARMED))
		return 0;
	__u32 tgid = ak_tgid();
	if (!ak_mcp_fd(tgid, ctx->args[0]))
		return 0;
	if (ak_is_self())
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 b = ctx->args[1];
	bpf_map_update_elem(&ak_pipe_read_args, &pt, &b, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int ak_stdio_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!(ak_flags_get() & AK_FLAG_MCP_ARMED))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 *b = bpf_map_lookup_elem(&ak_pipe_read_args, &pt);
	if (!b)
		return 0;
	if (ctx->ret > 0) {
		__u64 cgid = bpf_get_current_cgroup_id();
		ak_emit_tls(cgid, 1, (const char *)*b, (int)ctx->ret, 0);
	}
	bpf_map_delete_elem(&ak_pipe_read_args, &pt);
	return 0;
}
