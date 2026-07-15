<!-- SPDX-License-Identifier: Apache-2.0 -->
# Installing AgentKnox

AgentKnox runs on the host, either as a **systemd daemon** (primary) or as a **privileged Docker container** (at the end), and monitors AI coding agents running natively on that host. The agents are ordinary host processes, so there is no Kubernetes deployment and no CRD.

For an end-to-end first run, see [quickstart.md](quickstart.md). For every config key and the policy schema, see [configuration.md](configuration.md).

---

## Table of Contents

- [Quick Install (Debian/Ubuntu .deb)](#quick-install-debianubuntu-deb)
- [Prerequisites](#prerequisites)
- [Verify Your Environment](#verify-your-environment)
- [Step 1 — Build from Source](#step-1--build-from-source)
- [Step 2 — Place the Config File](#step-2--place-the-config-file)
- [Step 3 — Place a Policy](#step-3--place-a-policy)
- [Step 4 — Install the systemd Service](#step-4--install-the-systemd-service)
- [Step 5 — Verify the Install](#step-5--verify-the-install)
- [Docker Deployment](#docker-deployment)
- [Uninstall](#uninstall)
- [Next Steps](#next-steps)

---

## Quick Install (Debian/Ubuntu .deb)

The shortest path to a running service. Build the package once (needs Go 1.25+ and clang), then install it; the postinstall script enables and starts the unit for you.

```bash
make deb                                          # -> dist/agentknox_<version>_amd64.deb
sudo apt install ./dist/agentknox_*_amd64.deb     # or: sudo dpkg -i ./dist/agentknox_*_amd64.deb
```

The package lays down:

| Path | Contents |
|---|---|
| `/usr/bin/agentknox`, `/usr/bin/akctl` | daemon and CLI |
| `/lib/systemd/system/agentknox.service` | the unit, with `ExecStart` pointing at `/usr/bin/agentknox` |
| `/etc/agentknox/agentknox.yaml` | default config (a dpkg conffile, so your edits survive upgrades) |
| `/etc/agentknox/policies/` | empty policy directory, watched for `*.yaml` |
| `/usr/share/doc/agentknox/example-policy.yaml` | the shipped example policy |
| `/var/lib/agentknox/` | state directory for the WAL and the script archive |

Because the policy directory ships empty, the daemon starts in **observe-only** mode. Drop a `*.yaml` under `/etc/agentknox/policies` to begin enforcing; policies hot-reload.

```bash
systemctl status agentknox
akctl diagnose
```

Remove with `sudo apt remove agentknox` (keeps config) or `sudo apt purge agentknox` (removes config and state).

> The `.deb` needs the enforcement prerequisites at **runtime** (kernel 5.15+ with BTF, `bpf` in the LSM list) but only Go and clang at **build** time. It does not install an offset database or `signatures.json`; see [semantic-coverage.md](semantic-coverage.md) if you need semantic capture on a stripped agent build.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| CPU / OS | Linux **x86-64** (the eBPF programs use x86-64 register and stack conventions) |
| Kernel | **5.15+** with BTF at `/sys/kernel/btf/vmlinux`; verified on 6.8 |
| LSM backend (for kernel enforcement) | **`bpf`** present in `/sys/kernel/security/lsm` |
| io_uring observation (optional) | kernel **6.1+** with the `io_uring_submit_req` tracepoint; skipped if absent |
| Go (to build) | **1.25+** |
| eBPF toolchain (to build the BPF object) | **clang** + **llvm-strip** |
| Privileges (to run) | **root**, or the capability set below |

The daemon needs this capability set for eBPF load, BPF-LSM enforcement, cgroup management, network posture, and the userspace `Kill` effect. The shipped systemd unit grants exactly these:

```
CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_MAC_ADMIN CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_KILL
```

> **Enforcement requires BPF-LSM.** When `bpf` is not in `/sys/kernel/security/lsm`, the daemon selects the **userspace** backend, which cannot pre-block in the kernel. Its repertoire is alert plus kill: a `Block` verdict degrades to an alert, and a `Kill` verdict terminates the offending process or session with `SIGKILL` after the fact. Capture, correlation, and alerting are unaffected. See [troubleshooting.md](troubleshooting.md#a-block-rule-does-not-stop-the-operation).

> **BTF and clang are needed at different times.** BTF (`/sys/kernel/btf/vmlinux`) is a **runtime** requirement for CO-RE relocation. clang and llvm-strip are a **build-time** requirement only: the compiled eBPF object is embedded into the daemon with `go:embed`, so hosts that only run AgentKnox do not need a compiler.

---

## Verify Your Environment

```bash
# 1. Architecture and kernel version (need x86-64, 5.15+)
uname -m -r
# Expected: x86_64  5.15.x  (or higher)

# 2. BTF present (required at runtime)
ls -l /sys/kernel/btf/vmlinux
# Expected: the file exists

# 3. LSM list — 'bpf' must appear for in-kernel enforcement
cat /sys/kernel/security/lsm
# Expected: a comma-separated list containing 'bpf', e.g.
#   lockdown,capability,landlock,yama,apparmor,bpf

# 4. Build toolchain
go version        # go1.25 or higher
clang --version
llvm-strip --version
```

If `bpf` is missing from the LSM list, append it to the kernel command line and reboot, keeping every LSM your distribution already lists:

```
lsm=lockdown,capability,landlock,yama,apparmor,bpf
```

Add it through your bootloader (for GRUB, `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then `sudo update-grub`).

---

## Step 1 — Build from Source

```bash
git clone https://github.com/boanlab/agentknox.git
cd agentknox
make build
```

`make build` runs, in order: `bpf` (clang produces the embedded CO-RE object), `fmt`, `vet`, then builds `bin/agentknox`, `bin/akctl`, and `bin/agentknox-aggregator` with `CGO_ENABLED=0`.

| Target | What it does |
|---|---|
| `make bpf` | Compile the eBPF object only (needs clang + llvm-strip) |
| `make agentknox` | Build the daemon binary only |
| `make akctl` | Build the CLI binary only |
| `make aggregator` | Build the central aggregator binary only |
| `make offsetdb` | Generate or refresh the build-id → TLS offset database (`OUT=<path>`, default `/etc/agentknox/offsetdb`) |
| `make deb` | Build the Debian package into `dist/` (override the version with `DEB_VERSION=x.y.z`) |
| `make build-image` | Build the container image (`IMAGE`/`TAG` overridable) |
| `make test` | `go test ./... -count=1` |
| `make vet` / `make fmt` / `make gofmt` | `go vet`, `go fmt`, and the CI gofmt check |
| `make golangci-lint` / `make gosec` | Linter and security scanner |
| `make run` | Build, then `sudo -E bin/agentknox --log-level=debug` |

Confirm the binaries exist:

```bash
ls -l bin/agentknox bin/akctl bin/agentknox-aggregator
```

---

## Step 2 — Place the Config File

The daemon reads `agentknox.yaml` from the working directory (`.`) **or** `/etc/agentknox/`. The file is optional; without it the built-in defaults apply. Every key can also be overridden by an `AGENTKNOX_<KEY>` environment variable. For a service install, use the system path:

```bash
sudo mkdir -p /etc/agentknox
sudo cp deployments/agentknox.yaml /etc/agentknox/agentknox.yaml
```

The most relevant defaults:

| Key | Default |
|---|---|
| `mode` | `workstation` |
| `grpcAddr` (`AgentKnoxExport` gRPC service + health) | `:36920` |
| `policyDir` | `/etc/agentknox/policies` |
| `walDir` | `/var/lib/agentknox/wal` |
| `archiveDir` | `/var/lib/agentknox/scripts` |
| `offsetDBPath` | `/etc/agentknox/offsetdb` |
| `enforcerBackend` | `auto` |

Every key is documented in [configuration.md](configuration.md#config-keys).

---

## Step 3 — Place a Policy

The daemon loads every `*.yaml` file under `policyDir` at startup. With no policy directory it logs `no policy dir; running observe-only` and monitors without enforcing.

```bash
sudo mkdir -p /etc/agentknox/policies
sudo cp deployments/policies/example.yaml /etc/agentknox/policies/
```

> **Policies hot-reload.** The daemon watches the policy directory with fsnotify (debounced 500 ms) and recompiles on change, so no restart is needed after editing a policy. A malformed file is logged and skipped; the previously valid rule set stays in force.

Policy schema and worked examples: [configuration.md](configuration.md#policy-schema).

---

## Step 4 — Install the systemd Service

Install the binary where the shipped unit expects it, then the unit:

```bash
# The shipped unit's ExecStart is /usr/local/bin/agentknox
sudo install -m 0755 bin/agentknox /usr/local/bin/agentknox
sudo install -m 0755 bin/akctl     /usr/local/bin/akctl

sudo cp deployments/systemd/agentknox.service /etc/systemd/system/agentknox.service
sudo mkdir -p /var/lib/agentknox

sudo systemctl daemon-reload
sudo systemctl enable --now agentknox
```

The shipped unit (`deployments/systemd/agentknox.service`):

- runs `ExecStart=/usr/local/bin/agentknox --log-level=info`
- sets `AmbientCapabilities` and `CapabilityBoundingSet` to `CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_MAC_ADMIN CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_KILL`
- sets `LimitMEMLOCK=infinity`, required for eBPF map and ring-buffer memory
- restricts writable paths with `ReadWritePaths=/var/lib/agentknox /sys/fs/cgroup`
- restarts on failure (`Restart=on-failure`, `RestartSec=3`)

---

## Step 5 — Verify the Install

```bash
# Service is active
systemctl status agentknox

# Follow the daemon log
journalctl -u agentknox -f

# Health and served RPCs (gRPC)
akctl health      # -> health     SERVING
akctl diagnose    # daemon health + available RPCs
```

A healthy startup log carries `attached BPF-LSM enforcement hooks`, `enforce: InstallRules complete`, and either `policies loaded` or `no policy dir; running observe-only`. If it carries `not running as root; eBPF load and LSM enforcement will likely fail`, the daemon is unprivileged; fix that before continuing.

Now start a supported agent (`claude`, `codex`, `crush`, `gemini`, or `copilot`) and confirm the session appears:

```bash
akctl sessions
```

The full first-run walkthrough, including blocking a credential read, is in [quickstart.md](quickstart.md).

---

## Docker Deployment

Instead of systemd, AgentKnox can run as a **privileged container on the host**, monitoring the AI coding agents that run **directly on that host**. The agents are native host processes and do not run inside the AgentKnox container; the daemon excludes its own process from monitoring.

```bash
# The compose file bind-mounts ./policies relative to itself
mkdir -p deployments/docker/policies
cp deployments/policies/example.yaml deployments/docker/policies/

docker compose -f deployments/docker/docker-compose.yaml up --build -d
docker logs -f agentknox
```

The shipped compose service runs with:

| Setting | Value | Why |
|---|---|---|
| `pid` | `host` | the daemon reads the host `/proc` to attribute and re-arm session members |
| `network_mode` | `host` | the gRPC API binds the host's `:36920` |
| `cap_add` | `BPF PERFMON SYS_ADMIN NET_ADMIN MAC_ADMIN SYS_PTRACE SYS_RESOURCE` | eBPF load, BPF-LSM attach, cgroup and network posture |
| mounts | `/sys/kernel/{btf,debug,security}`, `/sys/fs/bpf`, `/sys/fs/cgroup`, `./policies` | BTF for CO-RE, tracefs, LSM state, pinned maps, cgroup v2, and the watched policy directory |

Policies hot-reload from the mounted directory exactly as in the systemd deployment. Reach the daemon with `akctl` from the host, or with `docker exec agentknox akctl ...` (the image ships `akctl` at `/usr/local/bin/akctl`).

---

## Uninstall

```bash
# systemd install from source
sudo systemctl disable --now agentknox
sudo rm /etc/systemd/system/agentknox.service /usr/local/bin/agentknox /usr/local/bin/akctl
sudo systemctl daemon-reload

# Docker
docker compose -f deployments/docker/docker-compose.yaml down

# Local config and state (both installs)
sudo rm -rf /etc/agentknox /var/lib/agentknox
```

For the `.deb`, use `sudo apt purge agentknox` instead, which removes the config and state for you.

---

## Next Steps

| Doc | Purpose |
|---|---|
| [quickstart.md](quickstart.md) | End-to-end first run with enforcement |
| [configuration.md](configuration.md) | Every config key plus the policy schema |
| [semantic-coverage.md](semantic-coverage.md) | Raising semantic coverage on stripped agent builds |
| [aggregator.md](aggregator.md) | Collecting events from many hosts |
| [troubleshooting.md](troubleshooting.md) | Symptom-indexed diagnostics |

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
