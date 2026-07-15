# Contributing to AgentKnox

Thank you for your interest in contributing to AgentKnox.

AgentKnox is a transparent, third-party runtime security monitor and policy enforcer for AI coding agents (Claude Code, OpenAI Codex CLI, Crush, Gemini CLI, GitHub Copilot CLI), built at the host kernel boundary with eBPF and BPF-LSM. This document covers the development environment, the build, the quality gates, and the PR rules. For what the system does and how it is deployed, start at [README.md](README.md).

## Prerequisites

AgentKnox is Linux x86-64 only.

| Requirement | Why |
|---|---|
| Go 1.25 | Userspace daemon, aggregator, and CLI |
| clang + llvm-strip | Only if you change anything under `bpf/`; `make bpf` needs a working `-target bpf` |
| Kernel 5.15+ with BTF (`/sys/kernel/btf/vmlinux`) | CO-RE relocation of the eBPF programs |
| `bpf` in `/sys/kernel/security/lsm` | Kernel enforcement; without it the daemon falls back to the post-hoc userspace backend |
| Root, or `CAP_BPF` + `CAP_SYS_ADMIN` | Loading the programs and running the daemon |
| Kernel 6.1+ (optional) | `io_uring` submission tracing; attached best-effort and skipped if absent |

The compiled CO-RE object `internal/sensor/agentknox_bpfel.o` is committed to the repository and embedded into the daemon with `go:embed`, so `go build ./...` and `go test ./...` work on a host with no LLVM toolchain at all.

---

## Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/your-username/AgentKnox.git
cd AgentKnox
git remote add upstream https://github.com/boanlab/AgentKnox.git

# 2. Build the eBPF object and the userspace binaries
make build     # bpf (clang), then fmt, vet, agentknox + akctl + aggregator

# 3. Run the daemon (needs root for eBPF and BPF-LSM)
sudo ./bin/agentknox --log-level=debug
./bin/akctl sessions      # inspect detected agent sessions

# 4. Create a branch and work
git checkout -b fix/your-bug   # or feature/your-feature
```

Without clang, substitute `go build ./...` for `make build`; the committed eBPF object keeps that working.

---

## Before Submitting a PR

Run the quality gates from the repository root:

```bash
make gofmt          # fails if any Go file is not gofmt-clean
make vet            # go vet ./...
make test           # go test ./... -count=1
make golangci-lint  # linter (config in .golangci.yml)
make gosec          # security scanner (exclusions documented in the Makefile)
make build          # full build, including the eBPF object
```

`.github/workflows/ci.yml` runs `make gofmt`, `go build`, `make vet`, `make test`, `golangci-lint`, and the SPDX license-header check on every pull request. Two gates it deliberately does **not** run, so you must run them yourself:

| Local-only gate | Why CI cannot run it | Command |
|---|---|---|
| eBPF object build | The hosted runner has no guaranteed `-target bpf` clang or `llvm-strip`, so a failure there would be unrelated to the change under review | `make bpf` |
| Root-gated kernel tests | Loading programs needs root, so these tests skip themselves on the runner | `sudo go test ./internal/sensor/` |

If you change anything under `bpf/`, run both on a kernel host before opening the PR. Regenerate the object with `make bpf` and commit it in the same change as the C it came from; CI cannot catch a verifier rejection.

---

## Coding Conventions

- **SPDX headers are required on every source file**, and the two identifiers must never be mixed:
  - Go and other userspace files carry `SPDX-License-Identifier: Apache-2.0`.
  - eBPF C sources and headers under `bpf/` carry `SPDX-License-Identifier: GPL-2.0`.
  - The dual-licensing is deliberate: the userspace Go code is Apache-2.0 and the in-kernel eBPF code is GPL-2.0. The header check is configured in `.licenserc.yaml`, which excludes `bpf/` for exactly this reason.
- Go code must be `gofmt`-clean and pass `go vet`; run `make fmt vet` before committing.
- The wire decoder (`internal/bpf2frame/`) is byte-locked to `bpf/wire.bpf.h`. If you change one, change the other in the same PR and bump `WireSchemaVersion`.
- The gRPC API is defined in `protobuf/agentknox.proto`. If you change it, run `make proto` (needs `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc`) and commit the regenerated stubs under `protobuf/agentknoxpb/` in the same PR.
- Keep the eBPF programs CO-RE-friendly and BTF-driven; do not hardcode kernel offsets outside the resolver's offset database.

---

## Commit and PR Guidelines

Commit messages follow `<type>(<scope>): <subject>`, for example `feat(sensor): add connect-exit pairing` or `fix(resolver): handle stripped BoringSSL build-id`. Common scopes mirror the tree:

| Scope | Area |
|---|---|
| `sensor` | eBPF loader, System Sensor, Semantic Sensor |
| `bpf2frame` | Wire decoder and syscall mapper |
| `resolver` | Semantic Attach Resolver and the offset database |
| `semantic` | Provider, MCP, and database-wire parsers |
| `session` | Session detection, normalization, and cgroup handling |
| `correlate` | Intent-effect join, taint propagation, mismatch detection |
| `policy` | Dual-layer policy engine and schema |
| `enforce` | BPF-LSM and userspace enforcement backends |
| `export` | Exporter, WAL, forwarding, aggregator |
| `akctl` | Control CLI |

Open PRs against `main` with a clear description and a linked issue. Keep them focused: unrelated changes belong in separate PRs. When you make a non-obvious design choice, or defer one for a maintainer to confirm, record the rationale in the PR description and, where it affects the architecture, in the relevant document under [docs/](docs/), so the reasoning is not lost.

---

## Where to Start

| What | Where |
|---|---|
| Open issues | [GitHub Issues](https://github.com/boanlab/AgentKnox/issues) |
| Architecture and end-to-end flows | [docs/architecture.md](docs/architecture.md), [docs/workflow.md](docs/workflow.md) |
| What is and is not covered | [docs/threat-model.md](docs/threat-model.md) |
| Test layout and how to run each tier | [tests/README.md](tests/README.md) |
| Security vulnerabilities | [SECURITY.md](SECURITY.md) |

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
