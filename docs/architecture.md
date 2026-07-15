<!-- SPDX-License-Identifier: Apache-2.0 -->
# AgentKnox Architecture

This document describes how AgentKnox is built: the planes it is divided into, the
components in each, how an event travels from a kernel hook to a policy decision,
and where each of those components lives in the tree. It is written for someone
reading or extending the code, or reviewing the design. For what AgentKnox does
and does not defend against, see [threat-model.md](threat-model.md); for the
step-by-step flows, see [workflow.md](workflow.md).

---

## Table of Contents

- [In one paragraph](#in-one-paragraph)
- [Design tenets](#design-tenets)
- [Plane model](#plane-model)
- [End-to-end data flow](#end-to-end-data-flow)
- [Session attribution](#session-attribution)
- [Policy architecture](#policy-architecture)
- [Kernel surface](#kernel-surface)
- [Technology choices](#technology-choices)
- [Deployment topologies](#deployment-topologies)
- [Trust boundary and self-protection](#trust-boundary-and-self-protection)
- [Repository layout](#repository-layout)

---

## In one paragraph

AgentKnox is a single host daemon that observes and constrains an AI coding agent
running natively on a developer machine, without modifying the agent. Two
uninstrumented sensors feed it. The **semantic sensor** attaches uprobes at the
agent process's own encryption boundary and lifts LLM and remote-MCP traffic as
plaintext; gated pipe hooks lift locally spawned MCP servers' JSON-RPC; the same
hooks lift plaintext database wire traffic on registered sockets. The **system
sensor** captures process, file, network, DNS, credential, and io_uring events
through tracepoints and BPF-LSM hooks. A userspace pipeline decodes and enriches
both streams, a **correlator** joins what the model asked for to what the system
actually did within one session, and a **dual-layer policy engine** evaluates the
pair. Decisions that need no further semantic context are compiled into kernel
maps and enforced by **BPF-LSM before the operation completes**; the rest are
decided in userspace and can escalate to an alert or a session kill. Everything
is exported over gRPC and to a JSONL write-ahead log.

---

## Design tenets

| # | Tenet | What it means in the code |
|---|---|---|
| 1 | **Boundary tracing** | Observe at interfaces that do not churn (the TLS library's read/write functions, syscalls, LSM hooks), never inside the agent's own volatile internals. |
| 2 | **Complete mediation** | Enforcement is a kernel BPF-LSM decision, not a cooperative hook the agent could decline. It binds children and indirect execution paths equally. |
| 3 | **Semantic-system fusion** | A policy predicate may reference both layers at once. The join is made from process lineage, a time window, and provenance labels. |
| 4 | **One control plane across agents** | Five agent CLIs are normalized into one `AgentSession` type, so a single policy governs all of them. |
| 5 | **Transparency** | No change to the agent's binary, configuration, hooks, or plugins. The daemon excludes itself from its own hooks. |
| 6 | **Honest coverage** | Where the boundary cannot see (a non-attachable TLS stack, a local model), the session says so. Coverage is decided from the plaintext the boundary actually delivered, not from what the attach plan reached, and kernel enforcement faults are counted and reported rather than swallowed. |

---

## Plane model

```
┌──────────────────────────────────────────────────────────────────────────┐
│ (D)  Policy and audit plane                                              │
│      Policy store (local YAML, fsnotify hot-reload) · validator          │
│      Exporter: gRPC AgentKnoxExport :36920 + JSONL WAL + recent ring     │
│      Script archive · forwarder → central aggregator :36930 · akctl      │
├──────────────────────────────────────────┬───────────────────────────────┤
│ (C)  Correlation and enforcement plane                                   │
│      Session Manager (AgentSession)                                      │
│      Correlator: intent↔effect join, lineage, taint, mismatch            │
│      Policy engine (dual-layer)  →  Enforcer (BPF-LSM | userspace kill)  │
├──────────────────────────────────┬───────────────────────────────────────┤
│ (A) Semantic capture plane       │ (B) System capture plane              │
│                                  │                                       │
│  Attach Resolver                 │  eBPF system sensor                   │
│   build-id fingerprint,          │   28 tracepoint programs              │
│   tier ladder T1..T7             │   12 BPF-LSM programs                 │
│  TLS uprobes                     │   1 kprobe (wake_up_new_task)         │
│   SSL_read/SSL_write, Go         │   → ak_events ring (4 MiB)            │
│   crypto/tls, AEAD boundary      │                                       │
│  stdio-MCP + DB pipe hooks       │  Wire decoder + syscall mapper        │
│   → ak_semantic ring (16 MiB)    │   (byte-locked to bpf/wire.bpf.h)     │
│  Provider / MCP / DB parsers     │                                       │
│  Transcript readers (fallback)   │                                       │
└──────────────────────────────────┴───────────────────────────────────────┘
       Both capture planes attribute every event to one AgentSession.
```

| Plane | Role | Packages |
|---|---|---|
| A — semantic capture | Recover the agent's intent as plaintext at the process's own boundary | `internal/resolver`, `internal/sensor` (semantic sensor), `internal/semantic`, `internal/rollout` |
| B — system capture | Capture the system effects in the kernel, uninstrumented | `bpf/`, `internal/sensor` (system sensor, loader), `internal/bpf2frame` |
| C — correlation and enforcement | Decide what happened and what to do about it | `internal/session`, `internal/correlate`, `internal/policy`, `internal/enforce` |
| D — policy and audit | Take policy in, put evidence out | `pkg/policyspec`, `internal/export`, `internal/archive`, `internal/forward`, `internal/aggregator`, `cmd/akctl` |

Plane A and the semantic-system fusion in plane C are what distinguish AgentKnox;
plane B, the enforcement backend, and the audit surface build on established eBPF
observation and enforcement technique.

---

## End-to-end data flow

```
   [ agent process and its descendants ]
        │                                   │
        │ TLS write/read (plaintext)        │ syscalls, LSM decisions
        ▼ uprobe / uretprobe                ▼ tracepoint / BPF-LSM
        │ pipe write/read on a              │
        │ registered MCP or DB fd           │
        ▼                                   ▼
   ┌──────────────────┐              ┌──────────────────┐
   │ ak_semantic ring │              │  ak_events ring  │
   │     (16 MiB)     │              │     (4 MiB)      │
   └────────┬─────────┘              └────────┬─────────┘
            │ ringbuf reader                  │ ringbuf reader
            ▼                                 ▼
     Semantic parser                    bpf2frame.Decode
      HTTP/2 stream demux,               → MapSyscall
      HTTP/1 de-chunk + inflate,         → SyscallEvent
      WebSocket permessage-deflate                │
      → provider / MCP / DB parse                 │
            │                                     │
            ▼                                     ▼
      SemanticEvent                    Session Manager: attribute every event
      (prompt, assistant, tool_use,     to an AgentSession by pid, then cgroup
       tool_result, mcp, db_query,                │
       usage)                                     │
            └────────────────┬────────────────────┘
                             ▼
                        Correlator
                         join tool_use to the syscalls it caused
                         (lineage + time window), propagate taint,
                         flag intent-effect mismatch
                             ▼
                     Policy engine (dual-layer)
                       → Allow | Audit | Alert | Block | Kill
              ┌──────────────┴───────────────┐
              ▼                              ▼
      Enforcer (kernel)              Exporter / WAL / archive
       BPF-LSM file_open, bprm,       gRPC AgentKnoxExport
       socket_connect, socket_        JSONL WAL + rotation
       sendmsg, path_* → -EPERM       forward → aggregator
       session kill (userspace)
              │
              ▼
      [ the syscall fails; the agent receives the failure as an ordinary
        tool_result error and replans ]
```

**Time relationship between the two paths.** A system event happens at the
syscall; the semantic event that explains it happened at the preceding model
round trip. The correlator matches a `tool_use` to subsequent syscalls in the same
session and lineage within a bounded window. Enforcement does not wait for that
join: an operation whose rule needs no semantic context is refused inside the LSM
hook, in the same syscall, from a kernel map that was populated when the policy
was compiled.

Two ring buffers carry everything: `ak_events` (4 MiB) for system events and
`ak_semantic` (16 MiB) for plaintext chunks, which is sized larger because a
streamed model response bursts many full-size chunks in flight. Ring-buffer
drops are counted and warned about rather than hidden, since a drop is a gap in
observation.

---

## Session attribution

Transparency rules out planting a marker in the agent, so membership is decided
from kernel identifiers. The **primary key is the per-pid map** `ak_session_pids`,
which is pid-precise and therefore works even when the agent shares a cgroup with
everything else on the desktop; the per-cgroup map is a secondary key.

| Step | Mechanism | Where |
|---|---|---|
| Detect | An exec whose `/proc/<pid>/exe` basename, `argv[0]` basename, or (for an interpreter launch such as `node /usr/bin/gemini`) a path component of the script argument matches an agent signature becomes a session root | `internal/session/manager.go` |
| Arm in kernel | The daemon writes the root pid, its tracked members, and every live descendant into `ak_session_pids` | `cmd/agentknox/daemon.go`, `internal/sensor/loader.go` |
| Arm at exec | The `bprm` LSM hook hashes the program's basename against a signature map and arms the tgid pre-userspace; a non-signature exec whose parent is already armed inherits there | `bpf/enforcer.bpf.c` |
| Arm at exec (argv) | The `execve` tracepoint scans up to four argv entries for a signature basename, then falls back to the armed session cgroup, then to an armed parent | `bpf/process.bpf.c` |
| Inherit at fork | A kprobe on `wake_up_new_task` tags every newly created task from its forking parent, covering every clone flavor (`fork`, `vfork`, `clone3`, `posix_spawn`); `sched_process_fork` covers the same ground for the flavors it sees | `bpf/process.bpf.c` |
| Recover | A 1.5-second userspace sweep re-arms every pid in the session cgroup, or walks `/proc` by parent pid, so a worker missed by the in-kernel paths is picked up | `cmd/agentknox/daemon.go` |
| Exclude self | The daemon's own tgid is written to `ak_self` at load; every hook returns immediately for it, and the session manager refuses to onboard its own pid | `internal/sensor/loader.go`, `internal/session/manager.go` |

Because the tag is planted in the **forking parent's context before the child can
run**, a double fork, a `setsid`, or a daemonize that reparents to init cannot
shed it. The semantic sensor's uprobes fire in the same processes, so both planes
land on the same session with no extra plumbing.

**Cgroup placement is optional and off by default.** When `manageCgroup: true`,
the session root is moved into `<cgroupParent>/session-<id>` (standard cgroup v2
delegation, out of band, requiring no cooperation from the agent) and the
directory inode becomes the session's cgroup id. With the default
`manageCgroup: false` the session uses whatever cgroup the agent was already in,
and attribution rests on the pid map.

---

## Policy architecture

Policies are declarative YAML files in a local directory (default
`/etc/agentknox/policies`), hot-reloaded on change via fsnotify with a 500 ms
debounce. A file that fails validation is skipped and reported; the rest stay in
effect. There is no CRD and no operator: the target environment is a developer
host, not a cluster.

A rule pairs an optional semantic predicate with an optional system predicate and
an optional condition:

```yaml
apiVersion: security.boanlab.com/v1
kind: AgentKnoxPolicy
metadata:
  name: example
spec:
  selector: ["claude-code", "codex", "crush", "gemini", "copilot"]   # or ["*"]
  defaultEffect: Allow
  rules:
    - name: no-egress-after-secret-read
      when:
        semantic:                 # tool, mcpMethod, provider, taint, provenance,
          taint: user-unseen      # intentClass, dbEngine, dbTable, dbOp
        system:                   # op, path, dir, cidr, fqdn
          op: connect
        condition:                # after, within, sessionState, coverage, tampered
          after: read
          within: 5s
      effect: Block               # Allow | Audit | Alert | Block | Kill
```

Rules are flattened across all loaded policies in load order and **the first match
wins**. `defaultEffect` applies when nothing matches, and the strongest
`defaultEffect` declared by any loaded policy is the one that takes effect.

**Where a rule is enforced** is decided at compile time:

| Rule shape | Enforced | Why |
|---|---|---|
| `effect: Block`, no `condition`, no `semantic`, `system.op` in {open, read, write, exec, delete, rename, chmod, chown} with an exact `path` or a `dir` | Kernel, pre-operation | The path hash is installed in `ak_enforce_file` / `ak_enforce_dir` and the LSM hook matches it locally |
| `effect: Block`, no `condition`, no `semantic`, `system.op: connect` with a concrete `cidr` | Kernel, pre-operation | The prefix goes into an LPM trie, IPv4 and IPv6 |
| `effect: Block`, no `condition`, `semantic.dbTable` set | Kernel, pre-operation | The denied table name is installed as a pattern the write hook matches on the outbound payload, and `socket_sendmsg` refuses the same send |
| Anything with `semantic` beyond `dbTable`, any `condition`, `effect: Kill`, a glob `path`, or an FQDN-only `connect` rule | Userspace, post-hoc | Session/history state and glob matching are not expressible in the kernel maps; installing them there would over-enforce |

An FQDN rule is still enforced in the kernel, but indirectly: DNS answers captured
at the resolver boundary are matched against `fqdn:` Block rules and the resolved
addresses are installed into the deny trie with TTL-based eviction, so the
following `connect` is refused pre-operation.

Cost is gated per session: a session whose cgroup and pids carry no enforce flag
takes an early return out of every LSM hook, and the global `ak_flags` bits keep
the host-wide `write`/`read` hooks to a single array lookup when neither
stdio-MCP nor database capture is armed.

---

## Kernel surface

| Kind | Count | Notes |
|---|---|---|
| BPF-LSM programs | 12 | `file_open`, `bprm_check_security`, `socket_connect`, `socket_sendmsg`, `path_unlink`, `path_rmdir`, `path_rename`, `path_chmod`, `path_chown`, `path_truncate`, `task_kill`, `ptrace_access_check` |
| Tracepoint programs | 28 | 27 attached unconditionally; `io_uring/io_uring_submit_req` is attached best-effort (it exists only on 6.1+ with io_uring enabled) |
| Kprobe | 1 | `wake_up_new_task`, attached best-effort |
| uprobe / uretprobe programs | 18 | `SSL_read`/`SSL_write`, Go `crypto/tls`, `EVP_AEAD_CTX_open`/`_seal`, and the ChaCha20-Poly1305 / AES-GCM assembly entry points |
| BPF maps | 29 | Two ring buffers, the session and posture maps, the enforcement rule maps, the provenance taint maps, the per-CPU path and DB scratch buffers, and the per-CPU fault counters |

`file_open`, `bprm_check_security`, and `socket_connect` are the **core** hooks:
each carries a whole class of Block decisions. If any of them fails to attach, the
daemon demotes itself to the post-hoc userspace backend rather than install kernel
rules that nothing will read. Losing any other hook narrows the envelope by
exactly one operation and is logged as such.

Everything is built into a single CO-RE object (`bpf/agentknox.bpf.c` is an
umbrella translation unit) that is committed and embedded with `go:embed`, so
building and testing the Go side needs no BPF toolchain. The object's wire header
`bpf/wire.bpf.h` is byte-locked to the Go decoder in `internal/bpf2frame`: change
one and you must change the other.

---

## Technology choices

| Area | Choice | Rationale |
|---|---|---|
| Userspace language | Go 1.25+, `CGO_ENABLED=0` | A single static binary with no runtime dependency |
| eBPF loader | `github.com/cilium/ebpf` | CO-RE, ring buffers, and LSM / kprobe / uprobe attachment from Go |
| BPF build | clang + `llvm-strip` into one umbrella TU, object committed and `go:embed`ed | Hosts without clang can still build, test, and run |
| Semantic capture | uprobes at `SSL_read`/`SSL_write`, Go `crypto/tls`, or the AEAD boundary, with offsets recovered from the build-id | No proxy, no MITM certificate, no change to the agent |
| Enforcement | BPF-LSM keyed on session membership, with a post-hoc userspace backend as fallback | Pre-operation denial in the kernel; the fallback is honest about what it cannot do |
| Wire contract | gRPC (`protobuf/agentknox.proto`: `AgentKnoxExport`, `AgentKnoxAggregator`) | Server streaming with a typed contract; `akctl` is a client |
| Audit storage | JSONL WAL with rotation, plus bbolt or PostgreSQL in the aggregator | A restart-safe local trail and an optional central store |
| Configuration | viper defaults → `agentknox.yaml` → `AGENTKNOX_*` environment overrides | One precedence chain; only `aggregatorAddr` is hot-applied |
| Logging | zap | Structured logs |
| Health | Standard gRPC health service | `akctl health` and `akctl diagnose` |

---

## Deployment topologies

The agents AgentKnox watches run as **native processes on a developer host**, not
inside containers or Kubernetes. AgentKnox therefore deploys onto that same host
and reads policy from local YAML.

| # | Topology | How | Use |
|---|---|---|---|
| 1 | systemd daemon | `make deb` → `dpkg -i`; the unit runs with `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_MAC_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_RESOURCE`, `CAP_KILL` and `LimitMEMLOCK=infinity` | The primary path on a developer workstation |
| 2 | Docker host container | `docker compose up` with `pid: host`, `network_mode: host`, the same capability set, and host mounts of `/sys/kernel/btf`, `/sys/kernel/debug`, `/sys/kernel/security`, `/sys/fs/bpf`, `/sys/fs/cgroup` plus the policy directory | A host that prefers not to install a package; the agents are still host-native |
| 3 | Direct run | `sudo bin/agentknox --log-level=debug` | Development and testing |
| — | Central aggregator | A separate `agentknox-aggregator` service on `:36930`, storing into bbolt or PostgreSQL, fed by each daemon's forwarder | Fleet-wide collection; see [getting-started/aggregator.md](../getting-started/aggregator.md) |

---

## Trust boundary and self-protection

The trusted computing base is the AgentKnox daemon plus the kernel. The agent and
its descendants are untrusted.

- **Self-protection is a kernel decision.** `InstallSelfProtection` writes the
  daemon's binary, config file, policy directory, WAL, and archive into the
  enforcement maps with the write, delete, rename, chmod, and chown operation
  bits, and tracks them separately from user rules so a policy hot-reload never
  drops them. `lsm/path_truncate` covers `truncate(2)` and `ftruncate(2)`, which
  reach a file's contents without opening it and would otherwise let an
  enforce-mode session member zero the policy file or the audit log past the
  write-open gate. `lsm/task_kill` and `lsm/ptrace_access_check` deny an
  enforce-mode session member from signalling or ptracing the daemon. The daemon
  is self-excluded, so it continues to manage all of these paths.
- **Kernel faults fail closed where a hook can refuse.** Path resolution runs into
  a per-CPU 1 KiB buffer; a target the kernel cannot render as an absolute path is
  refused for an enforce-mode member and counted. The exec-time session-arming
  write and the deny-egress arming write behave the same way. One fault does not
  refuse, and it is named rather than buried: a taint that cannot be stored under
  its path key. The precise list is in [threat-model.md](threat-model.md).
- **The gRPC API is unauthenticated and unencrypted.** The daemon binds
  `:36920` by default and `akctl` connects with insecure credentials. Bind it to
  a loopback address or protect it separately before exposing it beyond the host.
- **Prompt and code content stays local.** Capture is on by default and can be
  redacted with `capturePrompts: false`; nothing is sent off-host unless
  `aggregatorAddr` is configured.

---

## Repository layout

```
agentknox/
  bpf/                        umbrella TU plus per-feature .c/.h (system, semantic
                              uprobes, stdio/DB capture, enforcer), wire header
  internal/sensor/            eBPF loader, attach dispatcher, system and semantic
                              sensors, self-exclusion
  internal/bpf2frame/         wire decode and syscall/semantic mapping
                              (byte-locked to bpf/wire.bpf.h)
  internal/resolver/          attach resolver: build-id fingerprint, tier ladder,
                              offset DB, prologue signatures, binary identity
  internal/semantic/          provider, MCP, and DB wire parsers; HTTP/1, HTTP/2,
                              SSE and WebSocket framing
  internal/rollout/           on-disk session-transcript readers (content fallback)
  internal/session/           AgentSession lifecycle, agent normalization,
                              optional cgroup placement
  internal/correlate/         intent-effect join, lineage, taint, mismatch
  internal/policy/            load, validate, compile, evaluate; temporal markers
  internal/enforce/           BPF-LSM and userspace enforcement backends
  internal/export/            gRPC exporter (AgentKnoxExport), JSONL WAL, recent ring
  internal/archive/           preserves agent-written code at the moment it is run
  internal/forward/           batching forwarder to the central aggregator
  internal/aggregator/        central collection service (bbolt / PostgreSQL)
  internal/config/            agentknox.yaml load and hot-reload
  internal/pipeline/          the interface contracts between the components above
  pkg/types/                  SyscallEvent, SemanticEvent, CorrelatedAction,
                              Decision, AgentSession (public)
  pkg/policyspec/             AgentKnoxPolicy YAML schema (public, shared with the CLI)
  protobuf/                   agentknox.proto plus the committed generated stubs
  cmd/agentknox/              daemon assembly, MCP fd detection, offsetdb subcommand
  cmd/akctl/                  CLI
  cmd/agentknox-aggregator/   central collection daemon
  cmd/resolveprobe/           standalone resolver probe for debugging attach
  deployments/                systemd units, docker-compose, example policy and config,
                              shipped prologue signature database
  tests/                      integration script; see tests/README.md
```

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
