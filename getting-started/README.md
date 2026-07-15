<!-- SPDX-License-Identifier: Apache-2.0 -->
# Getting Started with AgentKnox

This guide gets you from a fresh Linux workstation to a running AgentKnox daemon with active dual-layer policy enforcement in about 15 minutes. By the end you will have:

- AgentKnox built and running as a host daemon (foreground or systemd)
- Detected `AgentSession`s for Claude Code / Codex CLI / Crush / Gemini CLI / GitHub Copilot CLI, inspected via `akctl`
- A policy that blocks an agent session from reading a credential file, enforced in BPF-LSM
- Live alert streaming over the daemon's gRPC API confirming the block

---

## Table of Contents

- [What is AgentKnox?](#what-is-agentknox)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quickstart (TL;DR)](#quickstart-tldr)
- [Documentation Map](#documentation-map)
- [Next Steps](#next-steps)

---

## What is AgentKnox?

AgentKnox is a transparent, third-party security monitor and policy enforcer for AI coding agents (**Claude Code, OpenAI Codex CLI, Crush, Gemini CLI, GitHub Copilot CLI**). It runs as a single host daemon and fuses two views of the same activity:

| Layer | What it captures | How |
|---|---|---|
| **Semantic** | prompts, model responses, `tool_use` / `tool_result`, MCP JSON-RPC, database queries | uprobes at the agent's TLS plaintext boundary (no MITM, no proxy), pipe capture for locally spawned stdio MCP servers, and wire-protocol parsing for MySQL / PostgreSQL / MongoDB |
| **System** | file, process, network, and database operations | eBPF tracepoints plus BPF-LSM hooks at the kernel boundary |

Its unit of control is the **agent session**, not the process or the user: a session is detected from the agent's exec, the tag is propagated in the kernel at fork and exec, and enforcement therefore binds every descendant (a spawned shell, a script, an MCP server child) rather than only the process that a user-space hook happened to see.

A correlation engine causally links intent to effect (process lineage, time window, provenance taint), a dual-layer policy engine evaluates `semantic × system × condition` predicates, and `Block` verdicts on system-layer predicates are enforced **pre-operation** in BPF-LSM.

> AgentKnox is a **research prototype**: no tagged release, and no API stability promise for the Go packages, the policy YAML schema, the gRPC contract, or the BPF wire format. Read [`../docs/threat-model.md`](../docs/threat-model.md) before relying on it: it states what the kernel boundary does and does not cover.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Workstation / Node                                          │
│                                                              │
│  [ AI coding agent + descendants ]                           │
│     │ TLS write/read (plaintext)      │ syscalls             │
│     ▼ uprobe at TLS boundary          ▼ tracepoint / BPF-LSM │
│  ┌───────────────┐                ┌───────────────┐          │
│  │ Semantic ring │                │ System ring   │          │
│  └───────┬───────┘                └───────┬───────┘          │
│          └──────────────┬─────────────────┘                  │
│                         ▼                                    │
│            Session Manager (AgentSession attribution)        │
│                         ▼                                    │
│            Correlation Engine (intent ↔ effect, taint)       │
│                         ▼                                    │
│            Policy Engine (dual-layer) → Enforcer (BPF-LSM)   │
│                         ▼                                    │
│            Exporter: gRPC AgentKnoxExport :36920 + WAL       │
└─────────────────────────┬────────────────────────────────────┘
                          │
                    akctl (sessions / stream / alerts / diagnose)
```

| Component | Role |
|---|---|
| `cmd/agentknox` | The daemon (composition root): sensors, resolver, session manager, correlation, policy, enforcement, export |
| `cmd/akctl` | gRPC client for the daemon's `AgentKnoxExport` service on `:36920` |
| `cmd/agentknox-aggregator` | Optional central collector for multi-host deployments (`:36930`) |
| BPF-LSM enforcer | Pre-operation denial of file, exec, and network operations in the kernel, scoped to session members |
| Exporter | `AgentKnoxExport` gRPC service, standard gRPC health, in-memory replay rings, and a JSONL write-ahead log |

---

## Prerequisites

| Requirement | Detail |
|---|---|
| CPU / OS | Linux **x86-64** |
| Kernel | **5.15+** with BTF at `/sys/kernel/btf/vmlinux` |
| LSM backend (for kernel enforcement) | **`bpf`** present in `/sys/kernel/security/lsm` |
| Go (to build) | **1.25+** |
| eBPF toolchain (to build the BPF object) | **clang** + **llvm-strip** |
| Privileges (to run) | **root**, or the capability set the shipped systemd unit grants |

Verify before proceeding:

```bash
# Architecture and kernel version
uname -m -r
# Expected: x86_64  5.15.x (or higher); verified on 6.8

# BTF present (required at runtime for CO-RE relocation)
ls -l /sys/kernel/btf/vmlinux

# LSM list — 'bpf' must appear for in-kernel enforcement
cat /sys/kernel/security/lsm
# Expected: a comma-separated list containing 'bpf'
```

Without `bpf` in the LSM list the daemon still captures, correlates, and alerts, but it falls back to the userspace backend: `Block` degrades to an alert and only `Kill` enforces (post-hoc `SIGKILL`). Full detail is in [installation.md](installation.md#prerequisites).

---

## Quickstart (TL;DR)

```bash
# 1. Build the eBPF object + the three binaries
make build

# 2. Drop the example policy in place
sudo mkdir -p /etc/agentknox/policies
sudo cp deployments/policies/example.yaml /etc/agentknox/policies/

# 3. Run the daemon (needs root for eBPF load + BPF-LSM attach)
sudo ./bin/agentknox --log-level=debug

# 4. In another terminal: inspect sessions, stream alerts, check health
./bin/akctl sessions
./bin/akctl stream --kinds alert
./bin/akctl diagnose
```

Start any supported agent (`claude`, `codex`, `crush`, `gemini`, `copilot`) and it appears as an `AgentSession` within a few seconds. The full walkthrough, including blocking a credential read, is in [quickstart.md](quickstart.md).

---

## Documentation Map

| Doc | Purpose |
|---|---|
| [installation.md](installation.md) | Prerequisites, `.deb` install, build from source, systemd service, Docker deployment |
| [quickstart.md](quickstart.md) | End-to-end: build → policy → run → `akctl` → block a credential read |
| [configuration.md](configuration.md) | Every `agentknox.yaml` key with default and meaning, plus the full policy YAML schema |
| [troubleshooting.md](troubleshooting.md) | Symptom-indexed diagnostics (eBPF load, enforcement, sessions, coverage, kernel faults, ports) |
| [aggregator.md](aggregator.md) | Multi-host: forward events to a central aggregator backed by bbolt or PostgreSQL |
| [semantic-coverage.md](semantic-coverage.md) | The offset resolver ladder, what `full` / `degraded` / `none` mean, and how to enable capture on stripped builds |

Design documentation lives in [`../docs/`](../docs): `architecture.md`, `workflow.md`, `threat-model.md`, and `related-work.md`.

---

## Next Steps

| Topic | Location |
|---|---|
| Full policy schema and daemon config reference | [configuration.md](configuration.md) |
| Semantic coverage levels and the resolver ladder | [semantic-coverage.md](semantic-coverage.md) |
| Symptom-indexed troubleshooting | [troubleshooting.md](troubleshooting.md) |
| Multi-host event collection | [aggregator.md](aggregator.md) |
| Threat model and coverage limits | [`../docs/threat-model.md`](../docs/threat-model.md) |
| gRPC API and Protobuf definitions | [`../protobuf/agentknox.proto`](../protobuf/agentknox.proto) |
| Contributing to the project | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Reporting security issues | [`../SECURITY.md`](../SECURITY.md) |

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
