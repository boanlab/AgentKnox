<!-- SPDX-License-Identifier: Apache-2.0 -->
# AgentKnox

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.25%2B-blue.svg)](https://golang.org/)
[![BPF](https://img.shields.io/badge/BPF-eBPF-green.svg)](https://ebpf.io/)

AgentKnox is a transparent runtime security monitor and policy enforcer for AI coding agents (Claude Code, OpenAI Codex CLI, Crush, Gemini CLI, GitHub Copilot CLI). It runs entirely at the host kernel boundary on eBPF and BPF-LSM, and needs no change to an agent's binary, configuration, hooks, or plugins.

Its unit of control is the **agent session**, not the process and not the user, so one rule denies the agent's read of a credential while the developer's read of the same file on the same host proceeds.

It fuses two layers. The **semantic layer** recovers the agent's model traffic as plaintext by attaching uprobes at the process's own TLS boundary (no proxy, no MITM certificate), and also lifts locally spawned MCP servers' JSON-RPC off stdio pipes and parses plaintext PostgreSQL, MySQL, and MongoDB wire traffic. The **system layer** supplies BPF-LSM file, exec, and network hooks, syscall and scheduler tracepoints, and kernel-side provenance labelling. A correlator joins what the model asked for to what actually happened, a dual-layer policy engine evaluates the pair, and `Block` and `Kill` decisions needing no further semantic context are compiled into kernel maps and enforced before the operation completes.

AgentKnox is a research prototype. There is no tagged release, and no API stability promise for the Go packages, the policy schema, the gRPC contract, or the BPF wire format.

| Layer | Captured at | Yields |
|---|---|---|
| Semantic | uprobes/uretprobes on the agent's own TLS boundary; gated read/write hooks on registered stdio-MCP pipes; plaintext DB wire; on-disk session transcripts as a fallback | prompts, model responses, `tool_use` / `tool_result`, MCP JSON-RPC, database queries |
| System | BPF-LSM hooks, syscall and scheduler tracepoints, a task-creation kprobe | file, exec, network, DNS, credential, and io_uring events; provenance and taint labels |

---

## Documentation

New to AgentKnox? Start here:

| Doc | Purpose |
|---|---|
| [getting-started/README.md](getting-started/README.md) | Entry point and reading order for the whole install path |
| [getting-started/installation.md](getting-started/installation.md) | Kernel prerequisites, `.deb`, systemd, and Docker install paths |
| [getting-started/quickstart.md](getting-started/quickstart.md) | First run: start the daemon, see a session, trip a policy |
| [getting-started/configuration.md](getting-started/configuration.md) | Every `agentknox.yaml` key and its environment override |
| [getting-started/semantic-coverage.md](getting-started/semantic-coverage.md) | The attach resolver, the offset DB, and why coverage degrades |
| [getting-started/aggregator.md](getting-started/aggregator.md) | Multi-host deployment behind the central aggregator |
| [getting-started/troubleshooting.md](getting-started/troubleshooting.md) | Symptom-indexed diagnostics for attach, capture, and enforcement |
| [docs/architecture.md](docs/architecture.md) | Components, planes, and how an event moves through them |
| [docs/workflow.md](docs/workflow.md) | End-to-end flows, including the policy appendix |
| [docs/threat-model.md](docs/threat-model.md) | Coverage matrix, closed gaps, and residual limits |
| [docs/related-work.md](docs/related-work.md) | How AgentKnox compares to adjacent tools |
| [tests/README.md](tests/README.md) | Unit, kernel-gated, and integration test layout |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development environment, quality gates, and PR rules |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and scope |

## Components

| Component | Location |
|---|---|
| eBPF programs (single umbrella TU) + wire format | [bpf/](bpf/) |
| eBPF loader, System Sensor, Semantic Sensor | `internal/sensor/` |
| Wire decoder / syscall mapper (byte-locked to `bpf/wire.bpf.h`) | `internal/bpf2frame/` |
| Semantic Attach Resolver (build-id to TLS offsets) | `internal/resolver/` |
| Semantic parsers (provider, MCP, database wire) | `internal/semantic/` |
| Session-transcript readers (content fallback) | `internal/rollout/` |
| Session Manager and agent normalization | `internal/session/` |
| Correlator (intent-effect join, taint, mismatch) | `internal/correlate/` |
| Dual-layer policy engine | `internal/policy/` |
| Enforcement backends (BPF-LSM, userspace fallback) | `internal/enforce/` |
| Exporter (`AgentKnoxExport` gRPC + JSONL WAL), script archive, forwarder | `internal/export/`, `internal/archive/`, `internal/forward/` |
| Aggregator service (gRPC ingest/query + bbolt or PostgreSQL store) | `internal/aggregator/` |
| Policy schema and shared event/session types | `pkg/policyspec/`, `pkg/types/` |
| `agentknox` daemon / `akctl` CLI / `agentknox-aggregator` | `cmd/agentknox/`, `cmd/akctl/`, `cmd/agentknox-aggregator/` |
| Deployment artifacts (systemd, Docker, example policy and config) | [deployments/](deployments/) |

---

## Quick Start

### Prerequisites

- Linux **x86-64** (the eBPF programs are compiled `-D__TARGET_ARCH_x86` and use x86-64 register conventions)
- Linux kernel **5.15+** with BTF at `/sys/kernel/btf/vmlinux`
- **`bpf` present in `/sys/kernel/security/lsm`** for kernel enforcement (check with `cat /sys/kernel/security/lsm`)
- Root, or `CAP_BPF` + `CAP_SYS_ADMIN`, to load the programs and run the daemon
- The agents run **natively on the same host**; they are not started inside AgentKnox
- Go 1.25 and clang + llvm-strip only if you build from source

Without `bpf` in the active LSM list the daemon still observes, but it falls back
to the userspace backend: enforcement becomes post-hoc, `Block` decisions degrade
to alerts, and only `Kill` actually stops anything. The daemon also re-checks
after attach and demotes itself the same way if a core hook fails to attach,
rather than installing kernel rules nothing reads. `io_uring` submission tracing
needs 6.1+ and is attached best-effort; it is skipped when the tracepoint is
absent.

### Install

```bash
git clone https://github.com/boanlab/AgentKnox.git
cd AgentKnox

# 1. Build the .deb (binaries + systemd unit, enabled and started on install)
make deb
sudo apt install ./dist/agentknox_*_amd64.deb

# 2. Edit the config it dropped at /etc/agentknox/agentknox.yaml
sudo $EDITOR /etc/agentknox/agentknox.yaml

# 3. Drop policies into the hot-reloaded policy directory
sudo cp /usr/share/doc/agentknox/example-policy.yaml /etc/agentknox/policies/

# Remove with: sudo apt purge agentknox
```

For a manual systemd install use [deployments/systemd/](deployments/systemd/)
with [deployments/agentknox.yaml](deployments/agentknox.yaml); for a privileged
host container (`pid` and `network` host, watching the host's agents) use
[deployments/docker/](deployments/docker/) or `make build-image`. Full paths and
trade-offs are in
[getting-started/installation.md](getting-started/installation.md).

**The shipped config enforces on install.** `dryRun` defaults to `false`, so a
session matching a `Block` or `Kill` rule is stopped, not merely alerted. Set
`dryRun: true` in `agentknox.yaml` to observe first. `capturePrompts` also
defaults to `true`, which writes raw prompt and response bodies into the local
WAL under `/var/lib/agentknox/wal`; turn it off on a host where prompt contents
must not be persisted.

### Verify

```bash
sudo systemctl status agentknox
akctl diagnose      # daemon health and the gRPC capabilities it serves
akctl sessions      # one row per session: ID, agent, PID, coverage, state
```

Start an agent (`claude`, `codex`, `crush`, `gemini`, `copilot`) in another
terminal; it appears in `akctl sessions` shortly after its first exec. A session
whose `COVERAGE` column reads `degraded` hooked its TLS boundary but is not
producing usable plaintext; see
[getting-started/semantic-coverage.md](getting-started/semantic-coverage.md).

---

## Policy

Policies are local YAML under the `security.boanlab.com/v1` API group, read from
`policyDir` and hot-reloaded on change. A file that fails validation is skipped
and reported while the rest stay in effect. Each rule pairs a **semantic**
predicate (tool, MCP method, provider, correlation taint, file provenance, intent
class, database engine/table/operation) with a **system** predicate (operation,
path, directory, CIDR, FQDN) and an optional **condition** (time window, session
state, semantic coverage, binary-identity flag), producing `Allow`, `Audit`,
`Alert`, `Block`, or `Kill`.

```yaml
apiVersion: security.boanlab.com/v1
kind: AgentKnoxPolicy
metadata:
  name: baseline-credential-protection
spec:
  selector: ["*"]            # claude-code | codex | crush | gemini | copilot | *
  defaultEffect: Allow
  rules:
    # Pure system rule, pre-enforced in BPF-LSM at file_open.
    - name: deny-ssh-private-key
      when:
        system:
          op: open
          path: "/root/.ssh/id_rsa"
      effect: Block

    # Dual-layer: a read-intent tool_use that reaches a tainted destination.
    - name: exfil-via-read-intent
      when:
        semantic:
          intentClass: read
          taint: sensitive
        system:
          op: connect
      effect: Kill

    # Provenance: code the session itself wrote may not be executed.
    - name: no-agent-written-code
      when:
        semantic:
          provenance: agent-written
        system:
          op: exec
      effect: Block

    # Coverage-adaptive: tighten posture when semantic observability drops.
    - name: tighten-when-blind
      when:
        system:
          op: connect
        condition:
          coverage: degraded
      effect: Alert
```

```bash
sudo cp my-policy.yaml /etc/agentknox/policies/
akctl policy          # list the rules the daemon currently holds
```

The full annotated example is
[deployments/policies/example.yaml](deployments/policies/example.yaml); the
schema itself lives in `pkg/policyspec/policyspec.go`.

Rules the kernel can decide alone are pushed down into BPF-LSM maps and enforced
pre-operation: `exec`, `open`, write-open, delete, rename, `chmod`, `chown`, and
truncate on files; IPv4 and IPv6 egress by CIDR, by FQDN resolved from captured
DNS answers with TTL eviction, and by a deny-egress posture armed when a session
reads a marked secret; and denied database tables refused in the same syscall,
before a byte reaches the transport. Rules needing semantic context the kernel
does not hold are decided in userspace and applied as a runtime verdict.

---

## Streaming Events and Alerts

The daemon serves the `AgentKnoxExport` gRPC service on `:36920`. `akctl` is a
client for it; `--addr` is a global flag and must precede the subcommand.

```bash
akctl --addr 127.0.0.1:36920 sessions      # active and past agent sessions
akctl stream --kinds semantic,alert        # live-tail exported envelopes as NDJSON
akctl alerts                               # recent Alert / Block / Kill decisions
akctl events --kind syscall --limit 100    # query the recent replay ring by kind
akctl health                               # gRPC health probe
```

Envelope kinds are `syscall`, `semantic`, `action`, `alert`, and `edge`.

Every exported envelope is also appended to a JSONL WAL with a durable cursor and
archive rotation, and scripts the agent writes and runs are copied into
`archiveDir` for forensics.

**The gRPC endpoints listen without authentication or transport encryption.**
Bind them to loopback or a trusted management network and do not expose them.
This is a documented limitation rather than an oversight to report as a
vulnerability; see [SECURITY.md](SECURITY.md).

---

## Multi-Host: Central Aggregator

One daemon logs and serves its own host. Across many hosts, set
`aggregatorAddr: <host>:36930` in each `agentknox.yaml` (hot-reloaded, so no
daemon restart) and each daemon forwards its events over gRPC to a central
aggregator that stores them in bbolt or PostgreSQL and serves a gRPC query API on
the same port.

```bash
docker compose -f deployments/aggregator/docker-compose.yaml up
```

See [getting-started/aggregator.md](getting-started/aggregator.md).

---

## Building from Source

```bash
make build     # eBPF object (clang), then fmt, vet, agentknox + akctl + aggregator
make test      # go test ./... -count=1
sudo ./bin/agentknox --log-level=debug
```

The compiled CO-RE object `internal/sensor/agentknox_bpfel.o` is committed and
embedded with `go:embed`, so `go build ./...` and `go test ./...` work on a host
with no LLVM toolchain. Only `make bpf` needs clang and `llvm-strip`; regenerate
and commit the object in the same change as the C it came from.

The kernel side is a single umbrella translation unit (`bpf/agentknox.bpf.c`,
which textually includes the rest): BPF-LSM programs for the enforcement hooks,
tracepoints and one kprobe for session lifecycle and capture, and
uprobe/uretprobe pairs for the plaintext boundary, all sharing one set of maps.
A new program is added there rather than as a second object.

`.github/workflows/ci.yml` runs the Go-side gates on every push to `main` and
every pull request: `make gofmt`, `go build`, `make vet`, `make test`,
`golangci-lint`, and the SPDX license-header check. It deliberately does **not**
run `make bpf` (the hosted runner's `-target bpf` clang and `llvm-strip` are not
guaranteed) and does **not** run the root-gated kernel tests under
`internal/sensor/` (they skip themselves when not run as root). Both stay a local
step on a kernel host, so run `make build` and `sudo go test ./internal/sensor/`
yourself whenever you touch `bpf/`.

---

## Coverage and Limits

The kernel boundary fixes what is observable, and several gaps are open by
construction: content piped straight into an interpreter never becomes a file and
so carries no provenance, the derived *code* label is keyed on path alone, and
enforcement that fails closed can cost a session its ability to spawn.

**Read [docs/threat-model.md](docs/threat-model.md) before relying on AgentKnox
for anything.** It states each gap, what closes it, and what does not.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development environment, the
quality gates, and the PR rules. Report vulnerabilities per
[SECURITY.md](SECURITY.md), never as public issues. This project follows the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0 for the userspace Go code, GPL-2.0 for the eBPF C under
`bpf/`. See [LICENSE](LICENSE).

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
