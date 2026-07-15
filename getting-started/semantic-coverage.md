<!-- SPDX-License-Identifier: Apache-2.0 -->
# Semantic Coverage and the Attach Resolver

AgentKnox lifts the model's own traffic (prompts, `tool_use`, `tool_result`, MCP JSON-RPC) out of TLS as plaintext, by attaching uprobes at the agent's TLS read/write boundary. No proxy, no MITM, no change to the agent. This document explains how that boundary is located, what the three coverage levels actually mean, and what to do when a session reports less than `full`.

By the end you will be able to:

- read the `COVERAGE` column of `akctl sessions` and know what it is asserting
- tell a resolver miss apart from a boundary that attached and delivered nothing
- supply an offset database entry or a prologue signature so a stripped agent build resolves
- write a policy that tightens posture exactly when AgentKnox goes semantically blind

For config keys, see [configuration.md](configuration.md). For symptom-indexed diagnostics, see [troubleshooting.md](troubleshooting.md).

---

## Table of Contents

- [The Resolver Ladder](#the-resolver-ladder)
- [What full / degraded / none Mean](#what-full--degraded--none-mean)
- [What Each Agent Actually Yields](#what-each-agent-actually-yields)
- [Binary Identity (tampered)](#binary-identity-tampered)
- [Symboled Libraries: Automatic](#symboled-libraries-automatic)
- [Stripped Builds: Build the Offset Database](#stripped-builds-build-the-offset-database)
- [Prologue Signatures Are Wildcard-Aware](#prologue-signatures-are-wildcard-aware)
- [Codex: The Assembly Boundary](#codex-the-assembly-boundary)
- [Go Agents: crypto/tls](#go-agents-cryptotls)
- [Where the Resolver Reads Its Inputs](#where-the-resolver-reads-its-inputs)
- [Using Coverage in Policy](#using-coverage-in-policy)

---

## The Resolver Ladder

A uprobe needs only a **file offset**, so the whole problem is recovering the offset of the boundary function in the agent's binary or its TLS library. The resolver tries the rungs below in order and stops at the first that succeeds. The `tier` and `boundary` names are the ones the daemon logs and stores on the session's attach plan.

| Rung | Technique | Reported `tier` | `boundary` |
|---|---|---|---|
| Go TLS | `crypto/tls.(*Conn).Read`/`.Write` from `.symtab`, falling back to `.gopclntab` | `T2-symtab` | `go-tls` |
| T1 | `.dynsym` lookup of `SSL_read` / `SSL_write` / `SSL_do_handshake` | `T1-dynsym` | `ssl` |
| T2 | `.symtab` lookup of the same symbols | `T2-symtab` | `ssl` |
| T3 | debuginfod fetch of separated DWARF, keyed by build-id | `T3-debuginfod` | `ssl` |
| T4 | build-id → offset database entry | `T4-offsetdb` | `ssl` or `aead` |
| T5 | prologue signature match against a symboled reference build | `T5-pattern` | `ssl` |
| T5 (AEAD asm) | prologue signature match against the CRYPTOGAMS AEAD kernels | `T5-pattern` | `aead-asm` |
| T6 | disassembly cross-reference from a resolved caller anchor | `T6-xref` | `ssl` |
| T7 | move the boundary down to `EVP_AEAD_CTX_open` / `_seal` | `T7-boundary` | `aead` |

Two behaviors matter in practice:

- **Late-loaded libraries are picked up.** The TLS library may not be mapped when the agent's exec is observed: `ld.so` may still be loading `NEEDED` libraries, or the agent may `dlopen` it lazily as Node and Python do. The daemon re-resolves and re-attaches on a short schedule (roughly 0.3 s, 1 s, 2 s, 4 s, 6 s) and upgrades the plan if a later attempt reaches further. Re-resolution never downgrades.
- **A distinct worker binary gets its own attach.** The root's uprobes are bound to the root's binary. When a session member execs a *different* agent binary (a Node launcher spawning a native worker that owns the TLS connections), that binary is resolved and attached separately, deduplicated per executable.

When no boundary can be reached at all, this is not an error. The resolver returns a valid `none` plan and system-layer capture and enforcement continue untouched.

---

## What `full` / `degraded` / `none` Mean

Coverage is decided by what the boundary actually **delivers**, not by what the attach plan hoped to reach.

| Level | Meaning |
|---|---|
| `full` | The boundary is attached in both directions **and** live plaintext has been recovered from it. |
| `degraded` | Either the plan reached only one direction, or the uprobes attached cleanly and the boundary yielded **no** live plaintext. Intent for that session is transcript-sourced. |
| `none` | No attach boundary was recovered, the attach failed, or `semanticEnabled: false`. |

**Attaching is not reading.** Two of the supported agents hook successfully and still deliver nothing parseable. The daemon therefore re-checks a session it first rated `full` after a 45-second grace period, chosen to comfortably exceed a cold agent's first model round-trip. If no semantic event has come off the live boundary by then, the session is downgraded to `degraded` and re-published to `akctl` and the audit trail:

```
attached boundary yielded no live plaintext; coverage downgraded to degraded
```

Content recovered from an on-disk session transcript does **not** count toward `full`. Only plaintext lifted at the live boundary does. This is what makes `when.condition.coverage: degraded` fire for exactly the sessions AgentKnox is genuinely blind on.

---

## What Each Agent Actually Yields

The ladder finds an attach boundary on **all five** supported agents. Live plaintext is lifted on **three** of them; the other two attach cleanly and deliver nothing usable, so their conversation content comes from the agent's own on-disk session records instead.

| Agent | TLS stack | Rung that resolves it | Live plaintext | Content source |
|---|---|---|---|---|
| Gemini CLI | Node's statically linked but symboled OpenSSL | `T1-dynsym` | Yes | live boundary, plus `~/.gemini/tmp` transcripts |
| Claude Code | stripped BoringSSL inside Bun | `T5-pattern` (signature) | Yes | transcripts under `~/.claude/projects`; the boundary supplies kernel-timed round-trip markers |
| Crush | Go `crypto/tls` | `T2-symtab` (`.symtab` or `.gopclntab`) | Yes | per-project SQLite session store at `<project>/.crush/crush.db` |
| Codex CLI | rustls + aws-lc-rs | `T5-pattern` on the AEAD assembly | No | `$CODEX_HOME/sessions/**/rollout-*.jsonl` (`$CODEX_HOME` defaults to `~/.codex`) |
| GitHub Copilot CLI | Node SEA; the TLS/HTTP-2/SSE path runs as JavaScript and WASM inside V8 | Node's exported SSL symbols, on the launcher and on its separately resolved native worker binary | No | `~/.copilot/session-state` |

Two caveats worth stating plainly:

- **Codex and Copilot are the two that deliver nothing.** Codex's AEAD dispatch yields decrypted TLS *records* rather than application messages, and its transport is a permessage-deflate WebSocket whose frames are only intermittently complete; Copilot's plaintext is produced and consumed inside V8, so it never crosses the native boundary the uprobes sit on. Both attach cleanly, both are downgraded to `degraded` once the grace period expires with no live plaintext, and both draw content from their transcripts.
- **Claude Code lifts plaintext but not reliably decodable content.** Its HTTP/2 plus SSE stream over stripped BoringSSL is not consistently reassembled, so the transcript is the authoritative content source there too, while the TLS boundary supplies trustworthy, kernel-timed round-trip markers. A transcript that disagrees with observed TLS timing is itself a tamper signal.

Transcript-sourced events go through the same policy, correlation, and export path as boundary-captured ones, and carry a `provider` label naming their reader (`codex-rollout`, `claude-transcript`, `gemini-transcript`, `copilot-transcript`, `crush-transcript`), so a policy can tell the two apart. Transcript readers are gated by `semanticEnabled` along with the wire sensor: setting it to `false` leaves the daemon in syscall-only operation.

---

## Binary Identity (`tampered`)

Identity is a separate signal from coverage, and it is decided for **every** resolved binary *before* the tier ladder descends. An unstripped agent that resolves at T1 is checked exactly like a stripped one that needs T4. A session is marked `Tampered` when either holds:

- a known-good reference set is loaded and the binary's build-id is absent from it; or
- the binary's code section matches one already resolved under a **different** build-id, so the identity changed while the code did not.

Neither fires when nothing could vouch for the binary in the first place (no reference set loaded and no prior sighting): silence is not evidence of tampering. The offset database doubles as the reference set, so populating it is what turns the first check on.

Use it in policy with `when.condition.tampered: true`. Omitting the key ignores the flag; it is not read as `false`.

---

## Symboled Libraries: Automatic

Agents using a dynamically linked, symboled OpenSSL (the system `libssl.so.3`) work out of the box through T1/T2, with nothing to configure. The same applies to a **statically embedded but symboled** OpenSSL: Node.js links its own OpenSSL into the `node` binary yet still exports `SSL_read` and `SSL_write` in the binary's symbol table, so Node-based agents such as Gemini CLI resolve directly at `T1-dynsym`. No offset database, no signatures.

---

## Stripped Builds: Build the Offset Database

Agents that statically embed a **stripped** BoringSSL (Claude Code) or use **rustls** (Codex) export no `SSL_read`/`SSL_write` names, so T1 and T2 cannot see them. Supply their offsets once per build, keyed by build-id, with the `offsetdb` subcommand; T4 then attaches automatically.

```bash
# Automatic — extract from a symboled binary/library, or from a running pid:
agentknox offsetdb --binary /lib/x86_64-linux-gnu/libssl.so.3 --out /etc/agentknox/offsetdb
agentknox offsetdb --pid 12345 --out /etc/agentknox/offsetdb

# Manual — recover the offsets offline (Ghidra/IDA) and record them against
# the binary's build-id. Valid keys: read, write, handshake, aead_open, aead_seal.
agentknox offsetdb \
  --set 'c30f169b...:read=0x1a2b3c,write=0x1a2b90' \
  --out /etc/agentknox/offsetdb
```

| Flag | Meaning |
|---|---|
| `--binary <path>` | Extract offsets from this binary's or library's symbols |
| `--pid <n>` | Extract from the TLS library that running process has mapped |
| `--set '<buildid>:key=0x..,…'` | Record a manual entry; keys are `read`, `write`, `handshake`, `aead_open`, `aead_seal` |
| `--out <path>` | Merge into this JSON file (and mirror to stdout). Without it, stdout only |
| `--signatures` | Emit a `signatures.json` of prologue patterns from `--binary` instead of an offset DB |
| `--siglen <n>` | Prologue length in bytes for `--signatures` (default 24) |

A stripped `--binary` yields nothing and says so: `no offsets recovered — the binary is stripped`. That is the case the signature path below exists for. `make offsetdb` runs the same subcommand and writes to `/etc/agentknox/offsetdb` unless you pass `OUT=<path>`.

**T5 prologue signatures** are the technique used to reach stripped Claude Code. Obtain the **symboled reference build** for the version the agent bundles (for Bun, its public "profile" build), extract prologue patterns from it, and T5 locates the same functions in the stripped release by matching the prologue and pinning read against write by their reference inter-function distance, which disambiguates thin wrappers that share an identical prologue:

```bash
agentknox offsetdb --signatures --binary ./bun-profile --out /etc/agentknox/signatures.json
```

---

## Prologue Signatures Are Wildcard-Aware

Extracted signatures **mask the operand bytes that vary between builds**: relative branch and RIP-relative displacements (exact, from the decoder) and immediates of two bytes or more (found by differential decode, where a byte is operand data if perturbing it leaves the opcode and length unchanged). Opcode, ModRM, SIB, and one-byte immediates such as stack-frame sizes stay fixed, because they are stable and make good discriminators.

Inter-function distances are only *locally* stable across versions: adjacent thin wrappers keep their spacing, but a distant function changing size shifts the pair. The solver therefore pins uniquely matched functions directly and resolves ambiguous ones against their nearest pinned neighbour.

The net effect is that **one signature covers a range of versions**. The shipped `deployments/signatures.json` carries `boringssl` prologue patterns and their reference offsets for `read`, `write`, and `handshake`, extracted from a Bun profile build; they were recorded as resolving a *later* Claude Code release that bundles a newer Bun than the reference. A matching profile build is therefore needed only when a boundary's prologue changes *structurally*, not on every version bump.

If a signature stops matching after an agent upgrade, the session drops to `none` and the resolver logs `resolver: no offsets recovered`. Re-extract from a profile build of the version the agent now bundles.

---

## Codex: The Assembly Boundary

Codex uses **rustls** with the **aws-lc-rs** crypto provider, so there is no `SSL_read` or `SSL_write` at all. The clean API boundary would be `EVP_AEAD_CTX_open` / `_seal`, but those C wrappers are register-allocation-sensitive: even a byte-exact reference (same `aws-lc-sys` crate, same clang version, release build) diverges from the agent's binary after roughly 20 bytes, because the build environment (`RUSTFLAGS`, target-cpu, vendored snapshot) is not reproducible. Prologue signatures cannot match them.

The layer below is stable. The AEAD ciphers are **CRYPTOGAMS hand-written assembly** (`chacha20_poly1305_open`/`seal`, `aesni_gcm_encrypt`/`decrypt`, `aes_gcm_encrypt_avx512`/`decrypt_avx512`). Being assembled rather than C-compiled, they are identical across compilers and flags, so one signature per `aws-lc-sys` version matches every build. AgentKnox attaches there, reading the plaintext buffer directly:

- `chacha20_poly1305_seal`, `aesni_gcm_encrypt`, `aes_gcm_encrypt_avx512` — plaintext is an **input**, read at entry (outbound).
- `chacha20_poly1305_open`, `aesni_gcm_decrypt`, `aes_gcm_decrypt_avx512` — plaintext is the **output**, read on return (inbound).

The host CPU picks the implementation (AES-NI versus AVX-512/VAES); all are hooked, so whichever fires is captured. The shipped `deployments/signatures.json` carries these under the `aws-lc-asm` provider. A new `aws-lc-sys` version needs a one-line re-extract from any symboled build of that version, identifiable by its `aws_lc_X_Y_Z` symbol prefix (a small `cargo build` of a crate depending on the same `aws-lc-rs` is enough):

```bash
agentknox offsetdb --signatures --binary ./libaws_lc_x_y_z_crypto.so --siglen 48 \
  --out /etc/agentknox/signatures.json
```

As noted above, this boundary yields decrypted TLS records rather than application messages, and Codex's transport is a permessage-deflate WebSocket. AgentKnox decodes those frames, but capturing every AEAD record of a long-lived WebSocket is intermittent, so the boundary is used mainly for kernel-timed round-trip markers while the session transcript supplies content. `internal/rollout` parses each transcript line into prompt, `tool_use`, and `tool_result` events and feeds them through the same policy, correlation, and export path.

---

## Go Agents: `crypto/tls`

Go binaries link the standard library's `crypto/tls`, so the boundary is `crypto/tls.(*Conn).Read` and `.Write`. Those names are read from `.symtab` when it is present, and from **`.gopclntab`** when it is not: the Go runtime's function table carries every function's name, entry, and end, and it survives a `-s -w` release build. That is why a stripped Go agent still resolves, at `T2-symtab`.

Because Go moves goroutine stacks, return probes are unsafe. `Write` is therefore read at entry, and `Read` at its `RET` instructions, located by disassembling the function; buffers follow the Go register ABI. This path is automatic for any Go agent that uses `crypto/tls`, with no reference build and no signature.

---

## Where the Resolver Reads Its Inputs

| Input | Path | Notes |
|---|---|---|
| Offset database | `offsetDBPath` (default `/etc/agentknox/offsetdb`) | JSON keyed by build-id. Also serves as the known-good reference set for `tampered` |
| Prologue signatures | `signatures.json` **in the same directory** as `offsetDBPath` | A missing file is not an error; the resolver logs `resolver: loaded T5 signatures` when it finds one |

Neither file is installed by the `.deb` or the container image. To use the shipped signatures, copy them into place:

```bash
sudo install -m 0644 deployments/signatures.json /etc/agentknox/signatures.json
sudo systemctl restart agentknox
```

---

## Using Coverage in Policy

Because coverage reflects what was actually delivered, a rule keyed on it fires precisely when the semantic view is missing. The shipped example policy carries this pattern:

```yaml
- name: tighten-when-blind
  when:
    system:
      op: connect
    condition:
      coverage: degraded
  effect: Alert
```

Whatever the coverage level, the **system layer is unaffected**: file, process, network, and database capture, provenance taint, and BPF-LSM enforcement all behave identically. A pure-system rule blocks just as hard on a `none`-coverage session as on a `full` one.

> **The fundamental limit:** stripping removes *names*, not code, so recovering a boundary's offset from a fully stripped binary needs a reference to match against. For a C boundary that reference must share the family and, loosely, the version; for a wrapper too build-sensitive to signature, the answer is to drop to the assembly, which is referenceable by version alone. An agent that uses a non-OpenSSL stack **and** keeps no local transcript is the residual case, and it is reported honestly as `none`.

---

## See also

- [configuration.md](configuration.md) — `offsetDBPath`, `semanticEnabled`, and the `coverage` / `tampered` predicates
- [troubleshooting.md](troubleshooting.md#semantic-coverage-is-degraded-or-none) — symptom-indexed coverage diagnostics
- [`../docs/threat-model.md`](../docs/threat-model.md) — the full coverage matrix and residual limits

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
