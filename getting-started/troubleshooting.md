<!-- SPDX-License-Identifier: Apache-2.0 -->
# Troubleshooting AgentKnox

Symptom-indexed diagnostics for the most common install, capture, enforcement, and streaming failures. Each entry names the symptom, then gives the checks, what a failing check means, and the fix.

For install and first run, see [installation.md](installation.md) and [quickstart.md](quickstart.md). For config keys and the policy schema, see [configuration.md](configuration.md).

> **First stop:** `akctl diagnose` reports whether the daemon is reachable and which RPCs it serves. `akctl events --kind <kind>` and `akctl alerts` show what the pipeline is actually producing. The daemon logs structured JSON, so `journalctl -u agentknox -o cat | jq` is the fastest way to read them.

---

## Table of Contents

- [Startup and eBPF Load](#startup-and-ebpf-load)
- [Sessions Are Not Detected](#sessions-are-not-detected)
- [Semantic Coverage Is Degraded or None](#semantic-coverage-is-degraded-or-none)
- [Enforcement Does Not Happen](#enforcement-does-not-happen)
- [Kernel Fault Counters](#kernel-fault-counters)
- [Policies Do Not Load or Apply](#policies-do-not-load-or-apply)
- [akctl and the gRPC API](#akctl-and-the-grpc-api)
- [Aggregator Forwarding](#aggregator-forwarding)
- [Collecting a Report](#collecting-a-report)

---

## Startup and eBPF Load

### The daemon exits at startup with a BPF load, verifier, or attach error

Work through these in order.

| Check | Failure meaning | Fix |
|---|---|---|
| `id -u` (or the log line `not running as root; eBPF load and LSM enforcement will likely fail`) | The daemon is unprivileged; eBPF load, BPF-LSM attach, and cgroup management all need privilege | Run with `sudo`, or install the systemd unit, which grants the capability set |
| `ls -l /sys/kernel/btf/vmlinux` | No kernel BTF, so CO-RE relocation cannot run | Install a distro kernel that ships BTF, or the matching `linux-image-*-dbg` / `kernel-debuginfo` package |
| `uname -r` | Kernel older than 5.15 | On Ubuntu: `sudo apt install --install-recommends linux-generic-hwe-22.04` |
| `uname -m` | Not `x86_64`; the eBPF programs use x86-64 register and stack conventions | AgentKnox targets x86-64 only |
| `ulimit -l` | Locked-memory limit too low for eBPF maps and ring buffers | The shipped unit sets `LimitMEMLOCK=infinity`; when running by hand, root normally lifts this, but a constrained shell may not |

### The log says `not running as root`

```
not running as root; eBPF load and LSM enforcement will likely fail
```

**Cause.** The daemon was started without privilege.

**Fix.** Run `sudo ./bin/agentknox`, or install the systemd unit, which grants:

```
CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_MAC_ADMIN CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_KILL
```

See [installation.md](installation.md#step-4--install-the-systemd-service).

### The log says an optional probe is unavailable

Two messages at startup are informational, not failures:

| Message | Meaning |
|---|---|
| `birth-time task arming unavailable (wake_up_new_task kprobe)` | The kprobe that arms a new task at birth did not attach. Clone-flavor worker spawns may be armed a moment later by the fork tracepoint or the periodic re-arm sweep instead. |
| `io_uring observation unavailable (needs the io_uring_submit_req tracepoint, kernel 6.1+)` | io_uring submissions are not observed on this kernel. Everything else is unaffected. |

---

## Sessions Are Not Detected

### `akctl sessions` prints `no sessions`

| Check | Failure meaning | Fix |
|---|---|---|
| Was the agent started **after** the daemon finished attaching? | Session onboarding follows the sensor attach, which takes a few seconds at startup | Wait for the attach sequence (visible at `--log-level=debug`), then start the agent, or restart the agent so a fresh `execve` is observed |
| `ps -o pid,comm,args -C claude` — does the program name match a signature? | Detection classifies on the **program name**, not on a substring of the command line | Matching is conservative: the executable basename (or, for `node /path/to/claude/cli.js`, an exact path component of the script argument) must equal a signature, or begin with `<signature>-` or `<signature>.` A binary that merely mentions "claude" in a later argument is not matched |
| Does your agent run under a custom launcher or wrapper name? | The wrapper's basename is not in `agentSignatures` | Add it and restart: `agentSignatures: ["claude","codex","crush","gemini","copilot","my-agent-wrapper"]` |
| Was the agent already running before the daemon started? | The `/proc` bootstrap scan adopts already-running agents, but it reads `/proc/<pid>/exe`, so an agent whose exe link is unreadable is missed | Restart the agent |

### A session appears, but a child process of it is not enforced

The session tag is propagated in the kernel at fork (`sched_process_fork`, plus a `wake_up_new_task` kprobe for clone flavors the tracepoint misses) and at exec (`bprm_check_security`). A periodic userspace sweep re-arms every live descendant every 1.5 s, which recovers a worker spawned through a reparent. If a child stays unenforced for longer than that, check the `arm_session` counter below: the per-pid session map may be full.

---

## Semantic Coverage Is Degraded or None

### `akctl sessions` shows `COVERAGE degraded`

**This is expected, not a failure.** Coverage reports what the plaintext boundary actually **delivered**, not what the attach plan reached. A session lands on `degraded` when either the resolver recovered only one direction, or the uprobes attached cleanly and the boundary yielded no live plaintext. The second case is why a session can start at `full` and be downgraded 45 seconds later: the daemon re-checks after a grace period that comfortably exceeds a cold agent's first model round-trip, and reports what it got.

```
attached boundary yielded no live plaintext; coverage downgraded to degraded
```

**What still holds.** Coverage describes the **semantic** layer only. The **system layer** (file, process, network, and database capture plus BPF-LSM enforcement) is unaffected. Pure-system policy rules enforce identically at any coverage level.

**What to do about it.** Either raise coverage by supplying the resolver with an offset database entry or a signature for that build ([semantic-coverage.md](semantic-coverage.md)), or tighten posture with a coverage-adaptive rule:

```yaml
- name: tighten-when-blind
  when:
    system: { op: connect }
    condition: { coverage: degraded }
  effect: Alert
```

### `akctl sessions` shows `COVERAGE none`

No attach boundary was recovered, or the attach failed. Check the resolver's own log line at `--log-level=debug`:

```bash
journalctl -u agentknox -o cat | jq -c 'select(.msg | test("resolver"))'
```

| Log message | Meaning | Fix |
|---|---|---|
| `resolver: no offsets recovered, degraded coverage` | The whole ladder missed: no symbols, no debuginfod, no offset-DB entry, no signature match | Add an entry for this build-id, or a signature from a matching reference build ([semantic-coverage.md](semantic-coverage.md)) |
| `attach uprobes failed; semantic capture unavailable for session` | Offsets were recovered but the uprobe attach failed after retries | Confirm the daemon can read the target binary and that the process is still alive |
| `resolver: load signatures failed` | The `signatures.json` beside `offsetDBPath` is malformed | Regenerate it with `agentknox offsetdb --signatures` |

`semanticEnabled: false` also produces `none` by design.

### A session is marked `tampered`

Binary identity is a separate signal from coverage, decided for every resolved binary before the tier ladder descends. A session is marked tampered when a loaded known-good reference set does not vouch for the build-id, **or** when the binary's code section matches one already resolved under a different build-id. Neither fires when nothing was available to vouch for the binary at all: silence is not evidence of tampering.

```
agent binary identity is not vouched for; session marked tampered
resolver: code section matches a build already resolved under a different build-id
```

An agent upgrade is the ordinary cause of the first form. Refresh the offset database for the new build.

---

## Enforcement Does Not Happen

### A `Block` rule does not stop the operation

| Check | Failure meaning | Fix |
|---|---|---|
| Is the operation performed by a **session member**? | Enforcement is scoped to the agent session's process tree, so an unrelated shell is not mediated | Trigger the operation from inside the agent (its shell tool, a spawned child, an MCP server child) |
| `cat /sys/kernel/security/lsm` | `bpf` absent, so the daemon selected the userspace backend, which cannot pre-block | Add `bpf` to the kernel LSM list and reboot (see below) |
| `journalctl -u agentknox \| grep 'core BPF-LSM'` | A core hook (`file_open`, `bprm_check_security`, `socket_connect`) failed to attach and the backend was demoted | See [core hooks](#the-log-says-core-bpf-lsm-hooks-unavailable) |
| `akctl policy` | The rule is not in the compiled set at all | The file failed validation; see [Policies Do Not Load or Apply](#policies-do-not-load-or-apply) |
| `journalctl -u agentknox \| grep 'kernel rule set is INCOMPLETE'` | The rule was compiled but the kernel refused to install it | See [the incomplete rule set](#kernel-rule-set-is-incomplete) |
| Does the rule carry a `when.condition` or a wildcard `path`? | Conditions and non-exact paths are never pre-installed in the kernel; they are evaluated in userspace and applied post-hoc | Expected. Use an exact absolute `path` or a `dir` prefix for pre-operation blocking |
| `dryRun` in `agentknox.yaml` | Dry-run mode never applies a verdict to the kernel | Set `dryRun: false` and restart |

The userspace backend announces itself explicitly:

```
BPF-LSM unavailable; using userspace (post-hoc kill) enforcement backend
enforce(userspace): Block not enforceable without BPF-LSM; alert only
```

**Fix for a missing `bpf` LSM.** Append it to the kernel command line, keeping every LSM your distribution already lists, and reboot:

```
lsm=lockdown,capability,landlock,yama,apparmor,bpf
```

After the reboot, `cat /sys/kernel/security/lsm` should include `bpf` and the daemon will select the BPF-LSM backend on the next start.

### The log says `core BPF-LSM hooks unavailable`

```
core BPF-LSM hooks unavailable; pre-operation enforcement cannot be honored,
falling back to post-hoc (kill) enforcement   hooks=[...] attached=[...]
```

**Cause.** The backend is chosen from the active LSM list before the programs attach, which cannot foresee a hook the kernel then declines. `file_open` (file rules, provenance taint, and the sensitive-source arm), `bprm_check_security` (exec), and `socket_connect` (all egress) are the hooks the pre-operation guarantee rests on. Losing any one of them would leave rules installed in maps that nothing reads, so the daemon demotes itself instead.

**Diagnose:**

```bash
journalctl -u agentknox -o cat | \
  jq -c 'select(.msg | test("BPF-LSM (enforcement hooks|hook unavailable)|core BPF-LSM"))'
```

Losing any *other* hook is logged separately and costs exactly one class of operation, left observed rather than refused:

```
BPF-LSM hook unavailable; the operations it mediates are observed, not refused   hook=...
```

### `kernel rule set is INCOMPLETE`

```
enforce: kernel rule NOT installed; this rule is not enforced   policy=... map=... category=... op=...
enforce: kernel rule set is INCOMPLETE; the dropped rules are not enforced in the kernel
                                                installed=N dropped=M skipped=K maps=[...]
install kernel rules   error=enforce: M of N block rules could not be installed (ak_enforce_file: M dropped (first: ...))
```

**What it means.** Every rule is attempted, so which rules are enforced never depends on their order in the policy file, but the rules named in those `Error` lines **are not enforced in the kernel**. The enforcement envelope in force is narrower than the policy you just loaded.

| `map` | What overflowed or was refused |
|---|---|
| `ak_enforce_file` | Exact-path file and exec rules |
| `ak_enforce_dir` | Directory-prefix rules |
| `ak_enforce_net` | CIDR egress rules (and the IPs resolved from `fqdn` rules) |
| `ak_db_deny_tables` | Denied database tables (a fixed number of slots) |

**Fix.** Reduce the number of distinct pre-installable `Block` rules: consolidate exact paths under a `dir` prefix, merge overlapping CIDRs, and drop denied tables you no longer need. A malformed CIDR also lands here; validate it and reload. Note that `skipped` is not an error: it counts rules that were never pre-installable (a wildcard path, a semantic predicate, a non-`Block` effect) and that the userspace evaluator handles.

### The agent's own `exec` starts failing with `EPERM`

**Cause.** Session arming **fails closed** in enforce mode. When the per-pid session map is full, the membership write is rejected, and a process that is not recorded as a session member is invisible to every later hook: its opens, execs, and connects would all run unmediated. Rather than start an agent outside its own enforcement envelope, the `bprm` LSM hook refuses the exec. A monitor-only session still starts, and emits an `<arm-failed>` process event so the hole is visible.

**Confirm it.** The `arm_session` fault counter grows and `<arm-failed>` events appear:

```bash
journalctl -u agentknox -o cat | jq -c 'select(.msg=="kernel enforcement fault" and .kind=="arm_session")'
akctl events --kind syscall --limit 200 | grep '<arm-failed>'
```

**Fix.** The map fills under very high fork or exec churn inside a session. Restarting the daemon clears it; the session that forks continuously is the thing to look at.

---

## Kernel Fault Counters

### The log carries `kernel enforcement fault` warnings

```
kernel enforcement fault   kind=path_unresolved since_last=3 total=41
```

**What it means.** The kernel hooks count the faults they could not act on, and the daemon reports the deltas periodically so a degraded envelope is visible rather than inferred. None is silent, but they do not all refuse the operation.

| `kind` | Meaning | Operation outcome |
|---|---|---|
| `path_unresolved` | The kernel produced no absolute path for a file or exec operation, so no rule, taint, or sensitive-source key could be formed | **Refused** for an enforce-mode session member |
| `arm_egress` | A sensitive-source read could arm deny-egress on neither the pid nor the cgroup (map exhaustion) | **Refused**, rather than handing the session an unguarded secret |
| `arm_session` | A session arming write was rejected because the per-pid session map is full | At the `bprm` hook the exec is **refused** for an enforce-mode session and an `<arm-failed>` event is emitted; a monitor-only session's exec proceeds unwatched. The same fault on the fork and execve tracepoints cannot be refused there, and leaves the child unmonitored until the re-arm sweep reaches it |
| `taint_store` | A provenance taint could not be stored under its path key | **Allowed.** The inode key still carries the bits the kernel sets on a write-open, so direct execution of an alias stays blocked, but a userspace-derived code label for that path is lost |
| `db_read` | An outbound database payload was unreadable, so the query went unmatched against the denied-table set | **Allowed**, and not matched. A denied table in that query is not blocked |

**What to do.**

| Counter behavior | Reading | Action |
|---|---|---|
| A few `path_unresolved` | Normal for pseudo-filesystem paths that have no `d_path` representation | None |
| Sustained `path_unresolved` growth with refused operations | Real operations are being refused for lack of a resolvable path | Inspect the `<unresolved>` events to see what the session is touching |
| Sustained `arm_session` or `arm_egress` growth | A kernel map is full, usually from very high fork or exec churn in a session | Restart the daemon to clear the maps, and investigate the session that forks continuously |
| Sustained `taint_store` growth | Provenance path keys are being dropped | Same cause as above; the inode-backed protection still holds |
| Any `db_read` | A database query was not readable at the capture point, so a per-table deny could not be applied to it | Treat per-table database denies as best-effort while this counter grows; the connection-level `connect` rules are unaffected |

---

## Policies Do Not Load or Apply

### The log says `no policy dir; running observe-only`

```
no policy dir; running observe-only   dir=/etc/agentknox/policies
```

**Cause.** `policyDir` does not exist. With no policies the daemon monitors and exports but enforces nothing.

**Fix:**

```bash
sudo mkdir -p /etc/agentknox/policies
sudo cp deployments/policies/example.yaml /etc/agentknox/policies/
```

> **Policies hot-reload.** The daemon watches the directory with fsnotify (debounced 500 ms). After adding or editing a `.yaml`, watch for `policy change detected; reloading` followed by `policies loaded  count=N`. If the directory could not be watched at all, the daemon logs `policy dir not watchable; hot-reload disabled` and you must restart after each edit.

### A policy file fails to load

```
policy load   file=<name>.yaml   error=validate ...: <reason>
```

The offending file is skipped and the other valid policies still load.

| Reason | Fix |
|---|---|
| `kind must be AgentKnoxPolicy` | Set `kind: AgentKnoxPolicy` |
| `metadata.name required` | Add `metadata.name` |
| `spec.selector required (use ["*"] for all agents)` | Add a non-empty `spec.selector` |
| `invalid defaultEffect` | Use one of `Allow Audit Alert Block Kill` |
| `rule[N].name required` | Give every rule a `name` |
| `rule "...": invalid effect` | Rule `effect` must be one of `Allow Audit Alert Block Kill` |
| `rule "...": at least one of when.semantic/when.system required` | Every rule needs a `when.semantic` and/or a `when.system` block |
| `rule "...": "..." is a provenance label; use when.semantic.provenance, not taint` | Move `agent-written` / `agent-code` from `taint` to `provenance` |
| `rule "...": invalid provenance "..."` | `provenance` accepts only `agent-written` or `agent-code` |

### `policy compile` fails and nothing is enforced

```
policy compile   error=policy "..." rule "...": invalid cidr "...": ...
```

**Cause.** Unlike a per-file validation error, a bad `when.system.cidr` fails the whole compile. No new rule set is installed, and the previously compiled set stays in force.

**Fix.** Correct the CIDR and save the file again; the watcher recompiles.

### A rule loads but never fires

| Check | Failure meaning | Fix |
|---|---|---|
| `akctl policy` | The rule is not listed, so it never compiled | See the two entries above |
| The `SELECTOR` column | The selector does not cover the session's agent kind | Use the normalized kind (`claude-code`, `codex`, `crush`, `gemini`, `copilot`) or `*` |
| Rule order | **The first matching rule wins**, so a broader earlier rule may be shadowing this one | Move the more specific rule earlier in the file, or into a file that loads first |
| The `LAYERS` column | A rule with a semantic layer needs a semantic event, which a `none`-coverage session may never produce | Pair it with a system predicate, or raise coverage |

---

## akctl and the gRPC API

### `akctl` cannot reach the daemon

```
akctl: sessions: ... (is the daemon running at 127.0.0.1:36920?)
```

or `akctl diagnose` prints `health: UNREACHABLE`.

| Check | Failure meaning | Fix |
|---|---|---|
| `systemctl status agentknox` | The daemon is not running | Start it, or check the foreground terminal |
| `sudo ss -ltnp 'sport = :36920'` | Nothing is listening on the API address | Confirm `grpcAddr` and that the daemon reached `Start` |
| The `--addr` you passed | `akctl` defaults to `127.0.0.1:36920` | Pass `--addr` **before** the subcommand: `akctl --addr 127.0.0.1:37020 diagnose` |

### The daemon cannot bind `:36920`

**Cause.** Another process holds the port: a second AgentKnox instance, or an unrelated service.

```bash
sudo ss -ltnp 'sport = :36920'
```

**Fix.** Change the address in `agentknox.yaml` and point `akctl` at it:

```yaml
grpcAddr: ":37020"
```

```bash
akctl --addr 127.0.0.1:37020 sessions
```

### `akctl stream` prints nothing

| Check | Failure meaning | Fix |
|---|---|---|
| Is a session active? | Capture is gated in the kernel to registered session members, so a host with no detected agent produces no events | See [Sessions Are Not Detected](#sessions-are-not-detected) |
| Is `--kinds` too narrow? | Only the listed kinds are delivered | Drop the flag to see every kind: `syscall`, `semantic`, `action`, `alert`, `edge` |
| Are you expecting alerts with no policy loaded? | Alerts come from policy decisions, so observe-only mode produces none | Load a policy, or stream `--kinds syscall` instead |
| Was the event produced before you connected? | `stream` is live-only | Use `akctl events --kind <kind> --limit N` to read the bounded replay ring |

---

## Aggregator Forwarding

### Events do not arrive at the central aggregator

| Check | Failure meaning | Fix |
|---|---|---|
| `aggregatorAddr` in `agentknox.yaml` | Forwarding is disabled when the key is empty | Set it to `host:36930`; it is hot-reloaded, so no restart is needed |
| `journalctl -u agentknox \| grep 'aggregator target changed'` | The daemon did not pick up the edit | Confirm the daemon actually loaded a config **file** (`AGENTKNOX_*` env-only setups have no file to watch) |
| Reachability from the monitored host to `:36930` | The aggregator is unreachable | Forwarding is best-effort and non-blocking: unreachable means events are dropped, never that the daemon stalls. The local WAL and gRPC API keep working |
| `Sources` on the aggregator | The host is not reporting at all | See [aggregator.md](aggregator.md#step-3--query-collected-events) |

---

## Collecting a Report

Include this in any bug report:

```bash
# Environment
uname -m -r; cat /sys/kernel/security/lsm; ls -l /sys/kernel/btf/vmlinux

# Daemon state
akctl diagnose
akctl sessions
akctl policy

# Recent daemon log (redact anything sensitive before sharing)
journalctl -u agentknox --since "30 min ago" -o cat > agentknox-log.json
```

Prompt and response text is captured into the WAL under `walDir` when `capturePrompts: true`; review and redact before sharing anything from there.

---

## See also

- [installation.md](installation.md) — prerequisites and service install
- [quickstart.md](quickstart.md) — end-to-end first run
- [configuration.md](configuration.md) — config keys and the policy schema
- [semantic-coverage.md](semantic-coverage.md) — the resolver ladder and coverage levels
- [`../docs/threat-model.md`](../docs/threat-model.md) — coverage matrix and known limits

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
