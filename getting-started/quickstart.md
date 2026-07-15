<!-- SPDX-License-Identifier: Apache-2.0 -->
# AgentKnox Quickstart

A single walk from source to a running daemon that detects your AI coding agents and blocks one of them from reading a credential file, enforced in the kernel with no changes to the agent. Budget about 15 minutes.

This runs AgentKnox in the foreground (no systemd) so you can watch it work. For the service install, see [installation.md](installation.md). For every config key and the full policy schema, see [configuration.md](configuration.md).

**Assumes** the [prerequisites](installation.md#prerequisites) are met: Linux x86-64, kernel 5.15+ with BTF, `bpf` in `/sys/kernel/security/lsm`, Go 1.25+, clang and llvm-strip.

---

## Table of Contents

- [Step 1 — Build the Binaries](#step-1--build-the-binaries)
- [Step 2 — Place a Policy](#step-2--place-a-policy)
- [Step 3 — Run the Daemon](#step-3--run-the-daemon)
- [Step 4 — Inspect Sessions](#step-4--inspect-sessions)
- [Step 5 — Stream Alerts and Check Health](#step-5--stream-alerts-and-check-health)
- [Step 6 — Block a Credential Read](#step-6--block-a-credential-read)
- [Step 7 — Clean Up](#step-7--clean-up)
- [Next Steps](#next-steps)

---

## Step 1 — Build the Binaries

```bash
git clone https://github.com/boanlab/agentknox.git
cd agentknox
make build
```

`make build` compiles the eBPF object with clang, runs `go fmt` and `go vet`, then builds three static binaries with `CGO_ENABLED=0`:

```bash
ls -l bin/agentknox bin/akctl bin/agentknox-aggregator
```

The compiled CO-RE object is embedded into the daemon with `go:embed`, so a host that only *runs* AgentKnox needs no clang.

---

## Step 2 — Place a Policy

The daemon loads every `*.yaml` file under its `policyDir` (default `/etc/agentknox/policies`) at startup, and watches the directory for changes afterwards. Start with the shipped example:

```bash
sudo mkdir -p /etc/agentknox/policies
sudo cp deployments/policies/example.yaml /etc/agentknox/policies/
```

`deployments/policies/example.yaml` demonstrates seven representative rule shapes: a pure-system pre-block, a dual-layer exfiltration kill, a provenance rule on agent-written code, a semantic-only MCP alert, an FQDN egress block, a coverage-adaptive alert, and an identity-adaptive block. We author our own credential-blocking policy in [Step 6](#step-6--block-a-credential-read).

With no policy directory at all the daemon logs `no policy dir; running observe-only` and monitors without enforcing.

---

## Step 3 — Run the Daemon

The daemon needs root for the eBPF load and the BPF-LSM attach:

```bash
sudo ./bin/agentknox --log-level=debug
```

`--log-level` is the daemon's only command-line flag; everything else comes from `agentknox.yaml` or `AGENTKNOX_*` environment variables. Logs are structured JSON on stderr. On a healthy start you will see, in order:

| Log message | Meaning |
|---|---|
| `agentknox starting` | version and `mode` from the config |
| `attached BPF-LSM enforcement hooks` | the `hooks` field lists every LSM program that attached |
| `enforce: InstallRules complete` | kernel rules derived from the policy were written to the BPF maps |
| `policies loaded` | `count` is the number of policy files compiled |
| `watching policy dir for changes` | hot-reload is armed |

Two startup messages mean you should stop and fix something:

- `not running as root; eBPF load and LSM enforcement will likely fail` — re-run with `sudo`.
- `core BPF-LSM hooks unavailable; pre-operation enforcement cannot be honored` — the kernel declined `file_open`, `bprm_check_security`, or `socket_connect`, and the daemon demoted itself to the post-hoc userspace backend. See [troubleshooting.md](troubleshooting.md#a-block-rule-does-not-stop-the-operation).

Leave this terminal running and open a second one for the rest.

---

## Step 4 — Inspect Sessions

Start any supported agent (`claude`, `codex`, `crush`, `gemini`, or `copilot`) in a normal shell. AgentKnox classifies it from its executable basename and command line and registers an `AgentSession`, usually within a few seconds.

```bash
./bin/akctl sessions
```

Example output:

```
ID        AGENT        PID    COVERAGE  STATE
a1b2c3d4  claude-code  48213  full      active
```

| Column | Meaning |
|---|---|
| `ID` | AgentSession id (UUIDv7) |
| `AGENT` | Normalized agent kind: `claude-code`, `codex`, `crush`, `gemini`, `copilot` |
| `PID` | Root PID of the agent process tree |
| `COVERAGE` | Semantic coverage: `full`, `degraded`, or `none` (see [semantic-coverage.md](semantic-coverage.md)) |
| `STATE` | Session lifecycle state: `active` or `ended` |

If you see `no sessions`, see [troubleshooting.md](troubleshooting.md#akctl-sessions-prints-no-sessions).

> `akctl` talks to the daemon over gRPC at `127.0.0.1:36920` by default. Override with the global `--addr host:port` flag placed **before** the subcommand: `akctl --addr 127.0.0.1:36920 sessions`.

---

## Step 5 — Stream Alerts and Check Health

Live-tail exported envelopes as NDJSON, filtered to alerts:

```bash
./bin/akctl stream --kinds alert
```

`stream` opens a server-streaming gRPC call and prints one JSON payload per line. Omit `--kinds` to see every kind; pass a comma-separated list to filter. The five envelope kinds are `syscall`, `semantic`, `action`, `alert`, and `edge`.

Print recent alerts from the in-memory replay ring, and probe daemon health:

```bash
./bin/akctl alerts
./bin/akctl diagnose
```

`akctl diagnose` reports reachability and the RPCs the daemon serves:

```
daemon: 127.0.0.1:36920
health: OK
capabilities (gRPC AgentKnoxExport):
  - ListSessions (akctl sessions)
  - Stream       (akctl stream)
  - Recent       (akctl alerts / events)
  - ListPolicies (akctl policy)
```

The full command set:

| Command | Purpose |
|---|---|
| `akctl sessions` | List active and recently ended `AgentSession`s |
| `akctl stream [--kinds k,k]` | Live-tail exported envelopes as NDJSON |
| `akctl alerts` | Print the last 100 alerts from the replay ring |
| `akctl events [--kind k] [--limit n]` | Query the replay ring by kind (default `alert`, limit 100) |
| `akctl policy` | List the compiled rules: name, selector, effect, and which layers each uses |
| `akctl health` | Probe the standard gRPC health service |
| `akctl diagnose` | Health plus the served RPCs |

Global flag: `--addr host:port` (default `127.0.0.1:36920`), placed **before** the subcommand.

---

## Step 6 — Block a Credential Read

Now author a policy that blocks any detected agent from reading a specific credential file. This is a **pure system rule**: `op: open` on an exact absolute path is pre-enforceable in BPF-LSM at `security_file_open`, so the open is refused with `EPERM` before it completes.

First create a decoy credential so nothing real is involved:

```bash
mkdir -p ~/.ssh && install -m600 /dev/null ~/.ssh/agentknox-demo-key
echo "not-a-real-key" > ~/.ssh/agentknox-demo-key
echo "$HOME/.ssh/agentknox-demo-key"
```

Write the policy, substituting the absolute path printed above. Paths must be absolute, exact, and free of glob characters for the kernel pre-block path:

```bash
sudo tee /etc/agentknox/policies/block-cred-read.yaml >/dev/null <<EOF
# SPDX-License-Identifier: Apache-2.0
apiVersion: security.boanlab.com/v1
kind: AgentKnoxPolicy
metadata:
  name: block-cred-read
spec:
  selector: ["*"]            # all agents: claude-code | codex | crush | gemini | copilot
  defaultEffect: Allow
  rules:
    - name: deny-demo-key
      when:
        system:
          op: open
          path: "$HOME/.ssh/agentknox-demo-key"
      effect: Block
EOF
```

The daemon watches the policy directory and reloads on change; watch the daemon terminal for `policy change detected; reloading` followed by `policies loaded` and `enforce: installed exact-path forbid rule`.

Now trigger it. **Enforcement is scoped to the agent session**, so the read must come from inside the agent's process tree; a `cat` typed in an unrelated shell is not a session member and is not mediated. Ask the running agent to read the file, or use its shell tool:

```
> read ~/.ssh/agentknox-demo-key and tell me what is in it
```

The read is refused (`Operation not permitted`, `EPERM`), and an alert appears on the `akctl stream --kinds alert` terminal. `akctl` prints the alert payload itself, one compact JSON object per line, with snake_case field names:

```json
{"alert_id":"01924f...","time":"2026-08-06T09:15:04.113Z","session_id":"a1b2c3d4","agent":"claude-code","severity":"critical","effect":"Block","policy_name":"block-cred-read","reason":"...","syscall":{"category":"file","operation":"open","resource":"/home/dev/.ssh/agentknox-demo-key","host_pid":48291}}
```

The same alert is retrievable afterwards with `./bin/akctl alerts`.

> **The point:** the block holds even when the agent reaches the file indirectly, through a spawned shell, a script, or an MCP server child. The session tag is propagated in the kernel at fork and at exec, and the decision is taken at the LSM hook, so there is no user-space hook to bypass and no process-name check to evade. To *observe without blocking* while tuning a policy, set `dryRun: true` (or `AGENTKNOX_DRYRUN=true`); see [configuration.md](configuration.md#dryrun).

---

## Step 7 — Clean Up

```bash
# Remove the demo policy (hot-reloaded away) and the decoy file
sudo rm /etc/agentknox/policies/block-cred-read.yaml
rm ~/.ssh/agentknox-demo-key

# Stop the daemon with Ctrl+C in its terminal, then remove local state if wanted
sudo rm -rf /var/lib/agentknox
```

---

## Next Steps

| Doc | Purpose |
|---|---|
| [configuration.md](configuration.md) | Every config key plus the full policy schema (semantic × system × condition) |
| [installation.md](installation.md) | Run AgentKnox as a systemd service or a privileged container |
| [semantic-coverage.md](semantic-coverage.md) | Why a session reports `degraded`, and how to raise coverage |
| [troubleshooting.md](troubleshooting.md) | When sessions, coverage, or enforcement do not behave |

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
