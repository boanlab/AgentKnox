// SPDX-License-Identifier: GPL-2.0
// network.bpf.c — outbound connect (captures destination, including refused).
#pragma once

// AK_SUN_MAX is the kernel's sun_path capacity for an AF_UNIX address.
#define AK_SUN_MAX 108

static __always_inline char ak_lc(char c)
{
	return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

// ak_unix_db_sock reports whether a filesystem socket path names a database
// server's listening socket. A local client (mysql, psql, mongosh) reaching its
// server over /var/run never carries a TCP port, so the port test that registers
// a remote DB socket cannot see it; the server socket NAME is the only signal the
// address carries. One bounded case-insensitive pass looks for the three
// well-known names ("…/mysqld.sock", "…/.s.PGSQL.5432", "…/mongodb-27017.sock").
// The wire protocol on the socket is identical to the TCP one, so a registered fd
// feeds the same capture and pre-op block path. An abstract socket (leading NUL)
// carries no such name and is not matched; a client socket that merely contains
// one of these tokens registers a capture the userspace wire parser then rejects,
// which costs a lookup and yields nothing.
static __always_inline int ak_unix_db_sock(const char *p)
{
	for (int i = 0; i + 5 <= AK_SUN_MAX; i++) {
		char a = ak_lc(p[i]);
		if (a == 0)
			break;
		char b = ak_lc(p[i + 1]), c = ak_lc(p[i + 2]);
		char d = ak_lc(p[i + 3]), e = ak_lc(p[i + 4]);
		if (a == 'm' && b == 'y' && c == 's' && d == 'q' && e == 'l')
			return 1;
		if (a == 'p' && b == 'g' && c == 's' && d == 'q' && e == 'l')
			return 1;
		if (a == 'm' && b == 'o' && c == 'n' && d == 'g' && e == 'o')
			return 1;
	}
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int ak_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;

	struct sockaddr *sa = (struct sockaddr *)ctx->args[1];
	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);

	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return 0;
	ak_fill_header(&r->hdr, cgid, ctx->id, AK_CAT_NETWORK);
	r->hdr.data_len = 0;

	__u16 dport = 0; // host-order destination port (for the DNS-socket check below)
	int unix_db = 0; // AF_UNIX destination that names a database server socket

	if (family == 1 /* AF_UNIX */) {
		// data layout: [family u16][zero port u16][sun_path...], so userspace
		// renders it as unix:<path> next to the ip:port forms.
		char sun[AK_SUN_MAX] = {};
		bpf_probe_read_user(sun, sizeof(sun), (const char *)sa + 2);
		__builtin_memcpy(&r->data[0], &family, 2);
		__builtin_memset(&r->data[2], 0, 2);
		__builtin_memcpy(&r->data[4], sun, AK_SUN_MAX);
		r->data[4 + AK_SUN_MAX - 1] = 0;
		r->hdr.data_len = 4 + AK_SUN_MAX;
		unix_db = ak_unix_db_sock(sun);
	} else if (family == 2 /* AF_INET */) {
		struct sockaddr_in sin = {};
		bpf_probe_read_user(&sin, sizeof(sin), sa);
		// data layout: [family u16][port be16][addr be32]
		__builtin_memcpy(&r->data[0], &family, 2);
		__builtin_memcpy(&r->data[2], &sin.sin_port, 2);
		__builtin_memcpy(&r->data[4], &sin.sin_addr, 4);
		r->hdr.data_len = 8;
		dport = bpf_ntohs(sin.sin_port);
	} else if (family == 10 /* AF_INET6 */) {
		struct sockaddr_in6 sin6 = {};
		bpf_probe_read_user(&sin6, sizeof(sin6), sa);
		__builtin_memcpy(&r->data[0], &family, 2);
		__builtin_memcpy(&r->data[2], &sin6.sin6_port, 2);
		__builtin_memcpy(&r->data[4], &sin6.sin6_addr, 16);
		r->hdr.data_len = 20;
		dport = bpf_ntohs(sin6.sin6_port);
	} else {
		__builtin_memcpy(&r->data[0], &family, 2);
		r->hdr.data_len = 2;
	}
	bpf_ringbuf_submit(r, 0);

	// Connected DNS socket: connect()+send() resolvers carry no per-write dest,
	// so the sendto hook misses them; mark the fd so the recv hooks capture the
	// answer.
	if (dport == 53) {
		__u64 fdkey = ((__u64)(bpf_get_current_pid_tgid() >> 32) << 32) | (__u32)ctx->args[0];
		__u8 one = 1;
		bpf_map_update_elem(&ak_dns_fds, &fdkey, &one, BPF_ANY);
	}

	// DB destination (a well-known TCP port, or a unix socket named after a
	// database server): mark the socket so outbound-write hooks lift plaintext wire
	// queries into the semantic ring; the armed flag keeps the write hook cheap
	// when no DB socket exists. Both forms register the same fd key, so a local
	// client over /var/run is captured and pre-op blocked like a remote one.
	if (unix_db || dport == 5432 || dport == 3306 || dport == 27017 ||
	    dport == 27018 || dport == 27019) {
		__u64 fdkey = ((__u64)(bpf_get_current_pid_tgid() >> 32) << 32) | (__u32)ctx->args[0];
		__u8 one = 1;
		bpf_map_update_elem(&ak_db_fds, &fdkey, &one, BPF_ANY);
		ak_flags_or_bit(AK_FLAG_DB_ARMED);
	}
	return 0;
}

// sendto(fd, buf, len, flags, dest_addr, addrlen): capture outbound DNS queries
// (dest port 53) so userspace can resolve domain <-> intent. The DNS payload is
// emitted; userspace parses the QNAME.
SEC("tp/syscalls/sys_enter_sendto")
int ak_sendto(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;

	struct sockaddr *sa = (struct sockaddr *)ctx->args[4];
	if (!sa)
		return 0;
	__u16 family = 0, port = 0;
	bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
	if (family != 2 /* AF_INET */)
		return 0;
	struct sockaddr_in sin = {};
	bpf_probe_read_user(&sin, sizeof(sin), sa);
	port = bpf_ntohs(sin.sin_port);
	if (port != 53)
		return 0;

	// Mark this socket fd as a DNS socket so the recvfrom-exit hook captures the
	// matching response (and only DNS responses).
	__u64 fdkey = ((__u64)(bpf_get_current_pid_tgid() >> 32) << 32) | (__u32)ctx->args[0];
	__u8 one = 1;
	bpf_map_update_elem(&ak_dns_fds, &fdkey, &one, BPF_ANY);

	const char *buf = (const char *)ctx->args[1];
	int len = (int)ctx->args[2];
	if (len <= 0)
		return 0;
	if (len > AK_MAX_STR)
		len = AK_MAX_STR;

	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return 0;
	ak_fill_header(&r->hdr, cgid, AK_PSEUDO_DNS_QUERY, AK_CAT_DNS);
	long n = bpf_probe_read_user(&r->data, len & (AK_MAX_STR - 1), buf);
	r->hdr.data_len = (n == 0) ? (__u32)(len & (AK_MAX_STR - 1)) : 0;
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// recvfrom(fd, buf, len, flags, src_addr, addrlen): stash the buffer pointer for
// a marked DNS socket so the exit hook can read the response once the kernel has
// filled it.
SEC("tp/syscalls/sys_enter_recvfrom")
int ak_recvfrom_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 fdkey = ((__u64)(bpf_get_current_pid_tgid() >> 32) << 32) | (__u32)ctx->args[0];
	if (!bpf_map_lookup_elem(&ak_dns_fds, &fdkey))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 buf = (__u64)ctx->args[1];
	bpf_map_update_elem(&ak_dns_read_args, &pt, &buf, BPF_ANY);
	return 0;
}

// recvfrom exit: emit the DNS response payload for userspace A/AAAA parsing.
SEC("tp/syscalls/sys_exit_recvfrom")
int ak_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 *bufp = bpf_map_lookup_elem(&ak_dns_read_args, &pt);
	if (!bufp)
		return 0;
	__u64 buf = *bufp;
	bpf_map_delete_elem(&ak_dns_read_args, &pt);

	long ret = ctx->ret;
	if (ret <= 0)
		return 0;
	int len = (int)ret;
	if (len > AK_MAX_STR)
		len = AK_MAX_STR;

	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;

	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return 0;
	ak_fill_header(&r->hdr, cgid, AK_PSEUDO_DNS_ANSWER, AK_CAT_DNS);
	long n = bpf_probe_read_user(&r->data, len & (AK_MAX_STR - 1), (const void *)buf);
	r->hdr.data_len = (n == 0) ? (__u32)(len & (AK_MAX_STR - 1)) : 0;
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// recvmsg(fd, struct msghdr *msg, flags): many resolvers (dig, glibc, systemd-
// resolved) connect() their UDP socket to :53 and use sendmsg/recvmsg rather than
// sendto/recvfrom, so the recvfrom hooks miss them. The DNS answer lands in the
// first iovec of the msghdr. Enter stashes that iovec base pointer (gated on the
// DNS-marked fd); exit emits the payload, mirroring the recvfrom path.
SEC("tp/syscalls/sys_enter_recvmsg")
int ak_recvmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 fdkey = ((__u64)(bpf_get_current_pid_tgid() >> 32) << 32) | (__u32)ctx->args[0];
	if (!bpf_map_lookup_elem(&ak_dns_fds, &fdkey))
		return 0;
	// Read msg->msg_iov, then iov[0].iov_base. struct msghdr: msg_name(0),
	// msg_namelen(8), msg_iov(16); struct iovec: iov_base(0), iov_len(8).
	void *msg = (void *)ctx->args[1];
	if (!msg)
		return 0;
	__u64 iovp = 0;
	if (bpf_probe_read_user(&iovp, sizeof(iovp), (char *)msg + 16) != 0 || iovp == 0)
		return 0;
	__u64 base = 0;
	if (bpf_probe_read_user(&base, sizeof(base), (void *)iovp) != 0 || base == 0)
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&ak_dns_read_args, &pt, &base, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_recvmsg")
int ak_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 *bufp = bpf_map_lookup_elem(&ak_dns_read_args, &pt);
	if (!bufp)
		return 0;
	__u64 buf = *bufp;
	bpf_map_delete_elem(&ak_dns_read_args, &pt);

	long ret = ctx->ret;
	if (ret <= 0)
		return 0;
	int len = (int)ret;
	if (len > AK_MAX_STR)
		len = AK_MAX_STR;

	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;

	struct ak_rec *r = bpf_ringbuf_reserve(&ak_events, sizeof(*r), 0);
	if (!r)
		return 0;
	ak_fill_header(&r->hdr, cgid, AK_PSEUDO_DNS_ANSWER, AK_CAT_DNS);
	long n = bpf_probe_read_user(&r->data, len & (AK_MAX_STR - 1), (const void *)buf);
	r->hdr.data_len = (n == 0) ? (__u32)(len & (AK_MAX_STR - 1)) : 0;
	bpf_ringbuf_submit(r, 0);
	return 0;
}
