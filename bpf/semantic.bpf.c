// SPDX-License-Identifier: GPL-2.0
// semantic.bpf.c — TLS plaintext capture via uprobes. These are attached by the
// loader at resolver-supplied offsets (func_name is irrelevant; SEC names are
// the attach handles). SSL_write(ssl, buf, num) / SSL_read(ssl, buf, num).
#pragma once

// rw_stash carries the read buffer pointer plus the connection object pointer
// from a read-entry hook to its return hook.
struct rw_stash {
	__u64 buf;
	__u64 conn;
};

// Stash the read buffer + connection pointer at entry so the return probe can
// read the decrypted bytes and tag them with their connection.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct rw_stash);
	__uint(max_entries, 8192);
} ak_ssl_read_args SEC(".maps");

// Same, for the Go crypto/tls.(*Conn).Read return probes.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct rw_stash);
	__uint(max_entries, 8192);
} ak_go_read_args SEC(".maps");

// ak_tls_rec is the semantic ring record: a header plus a large plaintext buffer
// (bigger than ak_rec's AK_MAX_STR path buffer) so a full TLS write is captured.
struct ak_tls_rec {
	struct event_t hdr;
	char data[AK_TLS_MAX];
};

// ak_emit_tls emits one plaintext chunk. conn is the TLS connection object
// pointer (SSL* / *tls.Conn), stored in retval so userspace can demultiplex
// concurrent connections that a single process runs (their HTTP/2 stream ids
// otherwise collide). 0 when no connection identity is available.
static __always_inline void ak_emit_tls(__u64 cgid, __s8 dir, const char *buf, int len, __u64 conn)
{
	if (len <= 0)
		return;
	// Bound the read size on an UNSIGNED variable so the verifier can prove R2 (the
	// bpf_probe_read_user size) lies in [0, AK_TLS_MAX-1]. Some clang versions lose
	// the non-negative range of the signed `len` otherwise ("R2 min value is
	// negative").
	__u32 rlen = (__u32)len;
	if (rlen > AK_TLS_MAX - 1)
		rlen = AK_TLS_MAX - 1;
	struct ak_tls_rec *r = bpf_ringbuf_reserve(&ak_semantic, sizeof(*r), 0);
	if (!r)
		return;
	__u64 pt = bpf_get_current_pid_tgid();
	r->hdr.event_type = AK_UNARY;
	r->hdr.category = dir; // 0 out / 1 in, reuse category byte for direction
	r->hdr.cpu_id = (__u16)bpf_get_smp_processor_id();
	r->hdr.timestamp = bpf_ktime_get_ns();
	r->hdr.cgroup_id = cgid;
	r->hdr.host_pid = pt >> 32;
	r->hdr.host_tid = (__s32)pt;
	r->hdr.syscall_id = (dir == 0) ? AK_PSEUDO_TLS_WRITE : AK_PSEUDO_TLS_READ;
	r->hdr.retval = (__s64)conn; // connection id for userspace demux
	long n = bpf_probe_read_user(&r->data, rlen, buf);
	r->hdr.data_len = (n == 0) ? rlen : 0;
	bpf_ringbuf_submit(r, 0);
}

// SSL_write(ssl, buf, num): plaintext outbound. ssl is the connection id.
SEC("uprobe/SSL_write")
int BPF_KPROBE(ak_ssl_write, void *ssl, const void *buf, int num)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 0, (const char *)buf, num, (__u64)ssl);
	return 0;
}

// SSL_read(ssl, buf, num): stash buf+ssl; emit on return with real length.
SEC("uprobe/SSL_read")
int BPF_KPROBE(ak_ssl_read_enter, void *ssl, void *buf, int num)
{
	__u64 flags = ak_session_flags(NULL);
	if (!(flags & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct rw_stash st = {.buf = (__u64)buf, .conn = (__u64)ssl};
	bpf_map_update_elem(&ak_ssl_read_args, &pt, &st, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(ak_ssl_read_exit, int ret)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct rw_stash *st = bpf_map_lookup_elem(&ak_ssl_read_args, &pt);
	if (!st)
		return 0;
	if (ret > 0)
		ak_emit_tls(cgid, 1, (const char *)st->buf, ret, st->conn);
	bpf_map_delete_elem(&ak_ssl_read_args, &pt);
	return 0;
}

// --- Go crypto/tls boundary (Go register ABI, e.g. Crush) -------------------
// Pure-Go TLS (crypto/tls) has no SSL_read/SSL_write; the plaintext boundary is
// crypto/tls.(*Conn).Read / .Write. Go's amd64 register ABI (1.17+) passes the
// receiver in RAX and the []byte slice in RBX(ptr)/RCX(len)/RDI(cap). Read args
// directly from pt_regs (BPF_KPROBE's PARM macros assume the C ABI, so they can't
// be used here).

// crypto/tls.(*Conn).Write(c, b []byte): the full plaintext is the slice at
// entry, so no return probe is needed.
SEC("uprobe/go_tls_write")
int ak_gotls_write(struct pt_regs *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 0, (const char *)ctx->bx, (int)ctx->cx, ctx->ax);
	return 0;
}

// crypto/tls.(*Conn).Read(c, b []byte) (n int, err error): the decrypted bytes
// land in b during the call, with n returned in RAX. Go moves goroutine stacks,
// which breaks uretprobe (and can crash the target), so the return is captured by
// uprobes on the function's RET instructions instead (offsets from the resolver).
// Keyed by pid_tgid: best-effort, since a read that parks and resumes on another
// thread is missed (Write already captures the request in full).
SEC("uprobe/go_tls_read_enter")
int ak_gotls_read_enter(struct pt_regs *ctx)
{
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct rw_stash st = {.buf = ctx->bx, .conn = ctx->ax};
	bpf_map_update_elem(&ak_go_read_args, &pt, &st, BPF_ANY);
	return 0;
}

SEC("uprobe/go_tls_read_ret")
int ak_gotls_read_ret(struct pt_regs *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	struct rw_stash *st = bpf_map_lookup_elem(&ak_go_read_args, &pt);
	if (!st)
		return 0;
	long n = (long)ctx->ax; // RAX = first return value (n)
	__u64 buf = st->buf, conn = st->conn;
	bpf_map_delete_elem(&ak_go_read_args, &pt);
	if (n <= 0)
		return 0;
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 1, (const char *)buf, (int)n, conn);
	return 0;
}

// --- AEAD boundary (T7: rustls/aws-lc-rs, e.g. Codex) ----------------------
// When there is no stable SSL_read, the plaintext record is at the AEAD layer:
// EVP_AEAD_CTX_open decrypts inbound (plaintext = out on return), and
// EVP_AEAD_CTX_seal encrypts outbound (plaintext = in on entry). Attached by
// offset (func_name irrelevant; SEC names are the attach handles).

struct aead_open_args {
	__u64 out;         // out buffer (plaintext lands here)
	__u64 out_len_ptr; // *out_len holds the decrypted length on return
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct aead_open_args);
	__uint(max_entries, 8192);
} ak_aead_open_args SEC(".maps");

// EVP_AEAD_CTX_open(ctx, out, out_len, max, nonce, nonce_len, in, in_len, ...)
// out=arg1(rsi), out_len=arg2(rdx) are registers; stash for the return probe.
SEC("uprobe/EVP_AEAD_CTX_open")
int BPF_KPROBE(ak_aead_open_enter, void *ctx_, void *out, void *out_len)
{
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct aead_open_args a = {};
	a.out = (__u64)out;
	a.out_len_ptr = (__u64)out_len;
	bpf_map_update_elem(&ak_aead_open_args, &pt, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/EVP_AEAD_CTX_open")
int BPF_KRETPROBE(ak_aead_open_exit, int ret)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct aead_open_args *a = bpf_map_lookup_elem(&ak_aead_open_args, &pt);
	if (!a)
		return 0;
	if (ret == 1) { // EVP_AEAD_CTX_open returns 1 on success
		__u64 len = 0;
		bpf_probe_read_user(&len, sizeof(len), (void *)a->out_len_ptr);
		ak_emit_tls(cgid, 1 /* inbound */, (const char *)a->out, (int)len, 0);
	}
	bpf_map_delete_elem(&ak_aead_open_args, &pt);
	return 0;
}

// EVP_AEAD_CTX_seal(ctx, out, out_len, max, nonce, nonce_len, in, in_len, ...)
// in=arg6, in_len=arg7 are passed on the stack (args 7/8). At the uprobe entry
// the return address is at [sp], so the first stack arg is at [sp+8].
SEC("uprobe/EVP_AEAD_CTX_seal")
int ak_aead_seal(struct pt_regs *ctx)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 sp = PT_REGS_SP(ctx);
	__u64 in = 0, in_len = 0;
	bpf_probe_read_user(&in, sizeof(in), (void *)(sp + 8));
	bpf_probe_read_user(&in_len, sizeof(in_len), (void *)(sp + 16));
	ak_emit_tls(cgid, 0 /* outbound */, (const char *)in, (int)in_len, 0);
	return 0;
}

// --- ASM AEAD boundary (Codex: rustls + aws-lc-rs) --------------------------
// The C EVP_AEAD_CTX_* wrappers are register-allocation-sensitive and cannot be
// located by prologue signature in a stripped custom-built binary; the underlying
// CRYPTOGAMS hand-written assembly (chacha20_poly1305_*, aesni_gcm_*) is
// byte-stable across builds and uniquely locatable, so it is the attach boundary.
// Attached by offset (func_name irrelevant; SEC names are the attach handles).

struct asm_out_args {
	__u64 out;  // plaintext output buffer
	__u64 len;  // requested length
	__u64 conn; // per-connection key/state pointer, used to demux connections
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct asm_out_args);
	__uint(max_entries, 8192);
} ak_asm_out_args SEC(".maps");

// The asm ciphers carry no SSL* to demux concurrent connections, so the
// per-connection key/state pointer (stable across a connection's records, unique
// between connections) is passed as the connection id instead.

// chacha20_poly1305_open(out, in, in_len, ad, ad_len, data): out=arg1 holds the
// decrypted plaintext on return; data=arg6 is the per-connection state.
SEC("uprobe/chacha20_poly1305_open")
int BPF_KPROBE(ak_chacha_open_enter, void *out, const void *in, __u64 in_len, void *ad, __u64 ad_len, void *data)
{
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args a = {};
	a.out = (__u64)out;
	a.len = in_len;
	a.conn = (__u64)data;
	bpf_map_update_elem(&ak_asm_out_args, &pt, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/chacha20_poly1305_open")
int BPF_KRETPROBE(ak_chacha_open_exit)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args *a = bpf_map_lookup_elem(&ak_asm_out_args, &pt);
	if (!a)
		return 0;
	ak_emit_tls(cgid, 1 /* inbound */, (const char *)a->out, (int)a->len, a->conn);
	bpf_map_delete_elem(&ak_asm_out_args, &pt);
	return 0;
}

// chacha20_poly1305_seal(out, in, in_len, ad, ad_len, data): in=arg2 is the
// plaintext at entry; data=arg6 is the per-connection state.
SEC("uprobe/chacha20_poly1305_seal")
int BPF_KPROBE(ak_chacha_seal, void *out, const void *in, __u64 in_len, void *ad, __u64 ad_len, void *data)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 0 /* outbound */, (const char *)in, (int)in_len, (__u64)data);
	return 0;
}

// aesni_gcm_decrypt(in, out, len, key, ...): out=arg2 holds the bulk plaintext on
// return; key=arg4 is the per-connection AES schedule. The return value is the
// number of bytes actually processed (the C remainder path handles the tail).
SEC("uprobe/aesni_gcm_decrypt")
int BPF_KPROBE(ak_aesgcm_dec_enter, const void *in, void *out, __u64 len, void *key)
{
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args a = {};
	a.out = (__u64)out;
	a.len = len;
	a.conn = (__u64)key;
	bpf_map_update_elem(&ak_asm_out_args, &pt, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/aesni_gcm_decrypt")
int BPF_KRETPROBE(ak_aesgcm_dec_exit, __u64 ret)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args *a = bpf_map_lookup_elem(&ak_asm_out_args, &pt);
	if (!a)
		return 0;
	__u64 n = ret ? ret : a->len; // bytes actually written to out
	ak_emit_tls(cgid, 1 /* inbound */, (const char *)a->out, (int)n, a->conn);
	bpf_map_delete_elem(&ak_asm_out_args, &pt);
	return 0;
}

// aesni_gcm_encrypt(in, out, len, key, ...): in=arg1 is the bulk plaintext at
// entry; key=arg4 is the per-connection AES schedule.
SEC("uprobe/aesni_gcm_encrypt")
int BPF_KPROBE(ak_aesgcm_enc, const void *in, void *out, __u64 len, void *key)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 0 /* outbound */, (const char *)in, (int)len, (__u64)key);
	return 0;
}

// AVX-512/VAES AES-GCM (used on AVX-512 hosts instead of aesni_gcm_*). Unlike
// the SSE stitched path, this processes the whole message in one call.
// aes_gcm_{encrypt,decrypt}_avx512(key, ctx, mres, in, len, out): key=arg1 is
// the per-connection AES schedule (reads [key+0xf0] rounds; stores plaintext
// via out=arg6). encrypt: in=arg4 is the plaintext at entry. decrypt: out=arg6
// holds the plaintext on return.
SEC("uprobe/aes_gcm_encrypt_avx512")
int BPF_KPROBE(ak_aesgcm512_enc, void *key, void *ctx_, void *mres, const void *in, __u64 len, void *out)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	ak_emit_tls(cgid, 0 /* outbound */, (const char *)in, (int)len, (__u64)key);
	return 0;
}

SEC("uprobe/aes_gcm_decrypt_avx512")
int BPF_KPROBE(ak_aesgcm512_dec_enter, void *key, void *ctx_, void *mres, const void *in, __u64 len, void *out)
{
	if (!(ak_session_flags(NULL) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args a = {};
	a.out = (__u64)out;
	a.len = len;
	a.conn = (__u64)key;
	bpf_map_update_elem(&ak_asm_out_args, &pt, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/aes_gcm_decrypt_avx512")
int BPF_KRETPROBE(ak_aesgcm512_dec_exit)
{
	__u64 cgid = 0;
	if (!(ak_session_flags(&cgid) & AK_SESS_MONITOR))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct asm_out_args *a = bpf_map_lookup_elem(&ak_asm_out_args, &pt);
	if (!a)
		return 0;
	ak_emit_tls(cgid, 1 /* inbound */, (const char *)a->out, (int)a->len, a->conn);
	bpf_map_delete_elem(&ak_asm_out_args, &pt);
	return 0;
}
