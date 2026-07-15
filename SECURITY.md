# Security Policy

## Supported Versions

AgentKnox is a research prototype under active development and has not yet cut a
tagged release. Security fixes land on the `main` branch; there is nothing older
to backport them to.

| Version | Supported |
|---|---|
| Latest `main` | Yes |
| Older commits | No |
| Forks | No |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues by email to **namjh@dankook.ac.kr** with the subject line `[AgentKnox Security]`.

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept
- Your environment: OS, kernel version (`uname -r`), BTF status (`ls /sys/kernel/btf/vmlinux`), LSM list (`cat /sys/kernel/security/lsm`), Go version, and the AgentKnox commit SHA
- Which AI coding agent was in use, if relevant (Claude Code, OpenAI Codex CLI, Crush, Gemini CLI, GitHub Copilot CLI)
- The affected component, if you can name it (see the scope table below)
- Any suggested mitigations you have

We aim to acknowledge reports within **5 business days**.

## Disclosure Policy

We follow a coordinated disclosure model. Please allow us reasonable time to
address the vulnerability before any public disclosure. We will credit reporters
in the release notes unless you prefer to remain anonymous.

---

## Scope

AgentKnox runs with elevated privileges and loads eBPF programs into the kernel,
so we take reports against the following seriously:

| In scope | Location | What we care about |
|---|---|---|
| eBPF / BPF-LSM programs and their loader | `bpf/`, `internal/sensor/` | Bypassing, corrupting, or crashing the in-kernel capture and enforcement path |
| Wire decoder and syscall mapper | `internal/bpf2frame/` | Memory or parsing faults on attacker-influenceable kernel event data |
| Semantic Attach Resolver and parsers | `internal/resolver/`, `internal/semantic/` | Faults or confusion when lifting and parsing plaintext from a monitored agent |
| Session detection and normalization | `internal/session/` | Escaping session membership; attributing an agent's action to the developer |
| Correlator and policy engine | `internal/correlate/`, `internal/policy/`, `pkg/policyspec/` | Intent-effect confusion; a rule that does not match what it plainly should |
| Enforcement backends | `internal/enforce/` | Policy bypass or enforcement evasion, including fail-open paths |
| Exporter, WAL, archive, forwarder, aggregator | `internal/export/`, `internal/archive/`, `internal/forward/`, `internal/aggregator/` | Data exposure beyond the documented posture below; WAL or archive tampering |
| Daemon, CLI, aggregator binaries | `cmd/agentknox/`, `cmd/akctl/`, `cmd/agentknox-aggregator/` | Privilege or argument handling |
| Deployment artifacts | `deployments/`, `packaging/` | Unsafe unit files, permissions, or defaults |

The following are **out of scope**:

- Third-party dependencies (report to the upstream project)
- The Linux kernel, the eBPF verifier, or the LSM frameworks themselves
- The monitored AI coding agents and their upstream providers
- Misconfigurations in user-supplied policy YAML
- Issues that require root on the host the daemon is already running on
- Reduced or degraded semantic coverage that AgentKnox reports honestly: a boundary that hooks but yields no usable plaintext is downgraded to `degraded` by design, and reporting a coverage gap is a feature, not a vulnerability

---

## Known Limitations (not vulnerabilities)

Two documented postures generate recurring reports. Both are limitations we
already state; a **bypass** that exposes data beyond them is in scope.

**Unauthenticated gRPC.** The daemon's `AgentKnoxExport` service (`:36920`) and
the `AgentKnoxAggregator` service (`:36930`) listen without authentication or
transport encryption. They are intended to be bound to loopback or a trusted
management network. Authentication and TLS for these endpoints are not yet
implemented.

**Prompt capture on disk.** `capturePrompts` defaults to `true`, so raw prompt
and response bodies are written to the local JSONL WAL under `walDir`
(`/var/lib/agentknox/wal` by default), and scripts the agent writes and runs are
copied into `archiveDir`. These files carry whatever the developer and the model
exchanged. Protect them like any other sensitive log, or set
`capturePrompts: false`.

The full coverage matrix and the residual limits of the enforcement boundary are
in [docs/threat-model.md](docs/threat-model.md).

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
