<!-- SPDX-License-Identifier: Apache-2.0 -->
# AgentKnox Threat Model and Coverage

This document states what AgentKnox observes and controls, what it has closed, and
what it has not. It is written for a security reviewer deciding whether the
guarantees hold, and for an operator deciding whether the residual gaps are
acceptable in their environment. Every claim below is meant to be checkable
against the code in `bpf/`, `internal/`, and `tests/`; where a mechanism is
partial, the limit is stated instead of being smoothed over.

AgentKnox observes and enforces at the **host kernel boundary**, without modifying
the agent. That transparency is a strength (no agent cooperation, no agent trust,
works on shipped binaries) and it also fixes what is observable: syscalls and LSM
decisions in the kernel, plaintext at the process's own TLS and pipe boundaries,
and nothing else.

---

## Table of Contents

- [1. What AgentKnox controls](#1-what-agentknox-controls)
- [2. Coverage matrix](#2-coverage-matrix)
- [3. Failure behaviour of the kernel hooks](#3-failure-behaviour-of-the-kernel-hooks)
- [4. Closed by implementation](#4-closed-by-implementation)
- [5. Residual limits — engineering-remaining](#5-residual-limits--engineering-remaining)
- [6. Residual limits — fundamental](#6-residual-limits--fundamental)
- [7. Agent privilege](#7-agent-privilege)
- [8. Design stance](#8-design-stance)

---

## 1. What AgentKnox controls

**The unit of control is the agent session**, not the process and not the user.
Every file open, exec, connect, delete, rename, mode change, and database send
made by the agent, by its children, and by anything it spawns indirectly is
mediated against the session's policy. A rule that denies a credential read denies
it for the session while the same read by the developer's own shell on the same
host proceeds, because the boundary keys on session membership rather than on the
uid or the path alone.

| | Scope |
|---|---|
| **Subject** | The AI coding agent and everything in its process tree — the thing observed and constrained. |
| **Adversary** | A misbehaving or manipulated agent acting through its ordinary tool interface (shell, file, network, MCP, database). The manipulation may come from prompt injection, a malicious or compromised MCP server, poisoned tool output or file contents, or plain model error and over-reach (`rm -rf`, secret exfiltration, `curl \| bash`, planting a backdoor). |
| **Asset** | The developer's system and data, protected from the agent's actions, per policy. |
| **Not in scope** | Hardening the host in general. AgentKnox is not an EDR or HIDS, does not defend against attackers other than the agent, and does not repair a pre-existing host compromise. The one adversary capability it does not claim to defeat is an escalation that **dismantles the enforcement mechanism itself** — kernel-level `CAP_BPF` / `CAP_SYS_ADMIN` used to detach or unload the BPF programs — which a deployment withholds from the agent ([§7](#7-agent-privilege)). |

Mediation does **not** depend on the agent being unprivileged. A session member
running as `root` is still gated by the same LSM hooks on the same maps; what
`root` buys the agent is only the ability to attack the enforcement machinery
directly, which is the one capability a deployment must withhold.

---

## 2. Coverage matrix

| Domain | Observe | Enforce (pre-operation, BPF-LSM) |
|---|---|---|
| Process exec | `tp/sys_enter_execve`, `tp/sys_enter_execveat`, `lsm/bprm_check_security` | `lsm/bprm_check_security` — denylist, provenance taint, anonymous-image refusal |
| Process fork | `tp/sched_process_fork`, `kprobe/wake_up_new_task` (tag inheritance) | — |
| Process exit | `tp/sched_process_exit` | — |
| File open | `tp/sys_enter_openat`, `tp/sys_enter_openat2`, `lsm/file_open` | `lsm/file_open` — read-open and write-open |
| File truncate | — | `lsm/path_truncate` — `truncate(2)` / `ftruncate(2)` reach contents without an open |
| File delete / rename | `tp/sys_enter_unlink[at]`, `tp/sys_enter_rename[at2]` | `lsm/path_unlink`, `lsm/path_rmdir`, `lsm/path_rename` |
| Directory create | `tp/sys_enter_mkdirat` | — |
| File chmod / chown | `tp/sys_enter_fchmodat`, `tp/sys_enter_fchownat` | `lsm/path_chmod`, `lsm/path_chown` |
| Network connect | `tp/sys_enter_connect`, `lsm/socket_connect` | `lsm/socket_connect` — IPv4 and IPv6 LPM denies from CIDR rules, runtime Block verdicts, and FQDN-resolved addresses with TTL eviction, plus the deny-egress posture |
| DNS | `tp/sys_enter_sendto`, `tp/sys_enter_recvfrom`, `tp/sys_exit_recvfrom`, `tp/sys_enter_recvmsg`, `tp/sys_exit_recvmsg` | — (answers feed the IP deny set above) |
| Database query | `tp/sys_enter_write` and `tp/sys_enter_sendto` on a registered DB socket | `lsm/socket_sendmsg` — a denied table or collection is refused in the same syscall, before a byte reaches the transport |
| Signals | `tp/sys_enter_kill` | `lsm/task_kill` — protects the daemon only |
| ptrace | `tp/sys_enter_ptrace` | `lsm/ptrace_access_check` — protects the daemon only |
| setuid | `tp/sys_enter_setuid`, `tp/sys_enter_setreuid` | — (observed) |
| io_uring | `tp/io_uring/io_uring_submit_req` (opcode granularity) | — (the file and network effects still traverse the LSM hooks above) |
| stdio MCP | `tp/sys_enter_write`, `tp/sys_enter_read`, `tp/sys_exit_read` on registered pipe fds | — (semantic verdicts escalate to system-layer enforcement) |
| Semantic (LLM, remote MCP) | uprobes at the TLS boundary; on-disk session transcript as a fallback | — (as above) |

Twelve BPF-LSM programs, 28 tracepoint programs, one kprobe, 18 uprobe/uretprobe
programs, and 29 BPF maps, in a single CO-RE object.

Attribution is scoped to the agent's process tree through the per-pid map
`ak_session_pids`, which is pid-precise and so works even when the agent shares a
cgroup with the rest of the desktop. The per-cgroup map is a secondary key.

---

## 3. Failure behaviour of the kernel hooks

The kernel counts five enforcement faults in a per-CPU array, and the daemon
reports them periodically. **Counted and refused are not the same thing**, and the
difference is the whole point of this table.

| Counter | What happened | What the hook does |
|---|---|---|
| `path_unresolved` | The kernel could not render an absolute path into the per-CPU 1 KiB buffer, so no rule, taint, or sensitive key can be formed for the operation | **Refused** for an enforce-mode session member |
| `arm_egress` | A read of a marked secret could arm deny-egress on neither the pid nor the cgroup (both map writes were rejected) | **Refused** — allowing the read would hand the session an unguarded secret |
| `arm_session` | A session-membership write was rejected because `ak_session_pids` is full | **Refused at `lsm/bprm_check_security`** for an enforce-mode session, with an `<arm-failed>` process event; a monitor-only session still execs, since refusing an exec is not a monitor session's contract. The fork and execve **tracepoints** have no veto, so there the fault is only counted and the userspace re-arm sweep recovers the child |
| `taint_store` | A provenance taint could not be stored under its path key | **Not refused.** The write proceeds. The inode key still carries the bits the kernel sets, but not the userspace-derived ones ([§5](#5-residual-limits--engineering-remaining)) |
| `db_read` | An outbound database payload was unreadable | **Not refused.** The query goes unmatched |

An exhausted `ak_session_pids` therefore costs an enforce-mode session its ability
to spawn, not its enforcement. The daemon warns on every non-zero delta, so a
degraded envelope is observable rather than inferred.

---

## 4. Closed by implementation

Each item below is implemented and has an automated test that drives the
mechanism. The kernel tests under `internal/sensor/` load the real BPF object,
attach the programs, and run a child process against them; they require root and
a BPF-LSM kernel and skip otherwise. See [../tests/README.md](../tests/README.md).

| Mechanism | Test |
|---|---|
| Self-protection: write, delete, rename, chmod, chown denied on the daemon's own paths | `TestSelfProtection` |
| `truncate` / `ftruncate` covered, so the policy file and audit log cannot be zeroed past the write-open gate | `TestTruncateSelfProtection` |
| Fork inheritance survives `setsid` and reparenting | `TestForkInheritance` |
| IPv6 egress denied by prefix | `TestIPv6Egress` |
| Persistence artifacts are surfaced, not blocked | `TestPersistObserveOnly` |
| A directory rule matches a target whose path exceeds the hooks' buffer | `TestLongPathEnforcement` |
| A wholly unresolvable path is refused and counted | `TestUnresolvablePathFailsClosed` |
| Re-registering a pid ORs its flags instead of downgrading an armed entry | `TestRegisterPIDPreservesArmedFlags` |
| `execveat(memfd, "", AT_EMPTY_PATH)` refused | `TestMemfdExecDenied` |
| A full session map refuses the exec rather than running it unarmed | `TestArmSessionFailsClosedWhenMapFull` |
| A unix socket named after a database server arms capture; one that is not, does not | `TestUnixSocketDBRegistered` |
| A denied query is refused pre-operation, including when its buffer ends at a page boundary | `TestDBQueryBlockedPreOperation`, `TestDBQueryBlockedAtPageBoundary` |
| Provenance survives copy, hard link, rename, symlink, extension disguise, and a never-before-seen path | `tests/integration/enforcement.sh` |

**Self-integrity as an enforcement property.** The daemon's binary, config, policy
directory, WAL, and archive are installed into the enforcement maps with the
write, delete, rename, chmod, and chown bits, tracked separately from user rules
so a policy hot-reload never drops them, and `lsm/task_kill` /
`lsm/ptrace_access_check` deny an enforce-mode session member from signalling or
ptracing the daemon. The daemon is self-excluded and keeps managing these paths.

**Anonymous in-memory images at exec.** A `memfd_create()` file is created by
`alloc_file_pseudo()` and never traverses `security_file_open`, so no write of the
session's can label it and neither provenance key exists at exec. It is the one
alias a session can produce that carries no label at all, so `execveat(memfd, "",
AT_EMPTY_PATH)` is refused on the *absence* of a path rather than on the presence
of one. This is the **exec** path only; a read of a memfd descriptor is not covered.

**Execution of an agent-written file survives aliasing.** The content-agnostic
write taint is set in the kernel on the write-open under both the path hash and
the inode's local storage, so a hard link, a rename, a mount-namespace alias, or
LRU eviction of the path key does not yield an alias that can be **executed**. The
narrower code taint that gates an interpreter's *read* is not equally robust
([§5](#5-residual-limits--engineering-remaining)). A provenance rule added by
hot-reload re-derives the deny-tainted-code flag and re-seeds the agent
signatures, so it takes effect on running sessions rather than staying inert.

**Honest backend selection.** The backend is first chosen from the active LSM
list, which cannot see a hook the kernel then declines. After attach, if
`file_open`, `bprm_check_security`, or `socket_connect` failed, the daemon demotes
itself to the post-hoc userspace backend instead of installing kernel rules that
nothing reads and reporting sessions as mapped into an enforcement domain that is
not there. Losing any other hook narrows the envelope by exactly one operation and
is logged as such.

**Attribution escape via reparenting.** Session membership is propagated to a
child **at task creation, in the forking parent's context, before the child can
run** — by a kprobe on `wake_up_new_task`, which the kernel calls for every clone
flavor, and by `tp/sched_process_fork`. A double fork, a `setsid`, or a daemonize
that reparents to init therefore cannot shed the tag: the child is already tagged,
with no exec and no userspace round trip involved.

**Delayed and out-of-tree execution.** An agent that writes a persistence artifact
(cron, systemd unit, at job, git hook, shell rc, autostart) taints that file. The
`bprm` hook then surfaces execution of the artifact **even by an out-of-tree
executor** such as cron or systemd that never belonged to the session, restoring
attribution of delayed execution. This is observation and attribution only;
blocking, if wanted, is an ordinary policy rule. The global check is gated by an
armed flag, so unrelated execs on the host pay nothing.

**stdio-transport MCP.** Local MCP servers exchange JSON-RPC over pipes, which
never cross the TLS boundary. Gated `sys_enter_write` / `sys_exit_read` hooks lift
the plaintext for fds the daemon registers (a session child whose stdin and stdout
are both pipes, confirmed by actually seeing JSON-RPC and evicted after 32 chunks
without it), feeding the same parser as TLS chunks. The parser side is covered by
a unit test; the pipe-capture path has no root-gated kernel test of its own.

---

## 5. Residual limits — engineering-remaining

Reducible with more work; currently partial or deferred.

**io_uring.** File and socket operations issued through io_uring still traverse
`lsm/file_open` and `lsm/socket_connect`, so enforcement holds for a monitored
session member. The `sys_enter_*` tracepoints are bypassed; submissions are
surfaced at opcode granularity only, and per-operation argument decode (paths,
addresses) remains coarse.

**Off-session runtime workers.** The LSM hooks gate on session membership. An
agent runtime that performs a read-and-send on completion threads placed outside
the session's pid set and outside the managed cgroup presents neither operation on
a monitored path, so the connect is neither observed nor pre-blocked. This is a
session-scope attribution gap rather than an io_uring or LSM bypass; it narrows as
capture is tightened to follow such workers, and does not arise for in-process
network paths or for tool children inside the session.

**stdio capture cost and scope.** `sys_enter_write` and `sys_enter_read` fire for
every such syscall on the host. The armed-flag check keeps the unarmed case to a
single array lookup, but it is not free. Capture assumes the MCP server uses fd 0
and fd 1; an unusual fd layout or a detection miss loses that stream. Behavioural
eviction bounds false positives, not false negatives.

**Fork-map churn.** Fork-time tagging adds an `ak_session_pids` entry per fork.
Leader-exit cleanup bounds it, but a fork bomb can exhaust the map. The userspace
arming call surfaces the map-full error naming the capacity, and the kernel counts
`arm_session`. Once exhausted, an enforce-mode session's execs are refused at
`bprm` rather than run unarmed ([§3](#3-failure-behaviour-of-the-kernel-hooks)); a
child born of a plain fork cannot be refused (a tracepoint has no veto) and stays
unmonitored until the re-arm sweep reaches it.

**Egress posture binds at connect, not at send.** The deny-egress posture armed by
a sensitive read is consulted in `lsm/socket_connect`. A socket the session
connected **before** the tainting read keeps sending, and connectionless
`sendto()` never reaches `security_socket_connect` at all. The read-then-connect
ordering a credential-exfiltration sequence actually needs is covered; a
pre-opened channel is not. DNS (port 53) is deliberately exempt from the blanket
deny so a tainted session can still resolve names without a retry storm.

**Tainted-code read denial does not test for an interpreter.** A read-open of a
file carrying the code taint is refused for any enforce-mode session member, not
only for an interpreter about to run it, so `cat` on such a file is refused too.
This over-blocks rather than under-blocks.

**The code taint is path-keyed when it comes from userspace.** The kernel sets the
code bit on a write-open only when the target inode already carries an execute
permission, and then records it under both keys. Every other code signal — a
shebang line, a known script extension, a later `chmod +x` — is detected in the
daemon and stored under the **path hash alone**. `path_rename` copies the
path-keyed bits to the new name, but there is no `lsm/path_link` hook, so a hard
link to a non-executable agent-written script carries the write taint on its inode
(still blocking direct exec) without the code bit, and an interpreter can read it
through the new name. Detection is also asynchronous: the daemon re-opens the file
to test for a shebang, so a file renamed or deleted first is never labelled.

**A read of an anonymous in-memory file is not covered.** The memfd refusal lives
in the exec hook only. `file_open` never tests for an anonymous image, and a memfd
resolves to a path no taint key was ever formed under, so an interpreter reading
the descriptor (for example through `/proc/self/fd/N`) is not refused.

**Content that never becomes a file carries no provenance.** Provenance is
recorded at `file_open`, so a payload piped straight from the agent into an
interpreter (`curl … | bash`, a heredoc, a FIFO) is never labelled. The stdio
hooks capture MCP and database traffic on explicitly registered descriptors; they
do **not** taint pipe contents, and no rule can be expressed over them. Pipe
laundering and descriptor reads are outside the provenance label.

**The sensitive-source label is name-based, and its two halves have different
reach.** A path is a sensitive source when it matches a secret pattern (`/.ssh`,
`.env`, `/.aws`, `credentials`, `id_rsa`, `id_ed25519`, `token`, `.pem`, `secret`,
`/.netrc`, `.kube/config`) and is neither public CA material, nor system code, nor
the agent's own provider store. Two mechanisms consume it:

- The **kernel deny-egress arm** fires on paths the daemon pre-marked in
  `ak_sensitive_files`. That marking happens **once, at session detection**, from
  a bounded scan (the agent's working directory to depth 4, skipping
  `node_modules`, `.git`, `vendor`, `.cache`, plus a fixed list of home secret
  locations). A secret created or staged *after* detection is not in that map and
  does not arm deny-egress in the kernel.
- The **userspace correlation label** is evaluated per event with the session's
  own write provenance consulted. This is where stage-and-read-back is closed:
  the agent-self-directory exemption covers the vendor's store as installed, not a
  file the session itself wrote there, so copying a secret into the agent's config
  directory and reading it back is still labelled. The vendors' own credential
  stores keep the exemption by **exact basename** (`.credentials.json`,
  `auth.json`, `oauth_creds.json`, `hosts.json`, `apps.json`, the gcloud ADC
  files), so an OAuth token refresh does not sever the agent's egress to its own
  model.

What remains outside the label either way: a secret staged under a name that
matches no pattern, and a secret **renamed** into place (the rename hook reports
the source path, so the destination is never recorded as session-written).
Provenance for **execution** does follow those moves, through the kernel's path
and inode taint ([§4](#4-closed-by-implementation)).

**Database capture is keyed on well-known destinations, and only partly proven.**
A socket registers for wire-protocol capture when it connects to a PostgreSQL,
MySQL, or MongoDB TCP port, or to a unix socket whose `sun_path` contains
`mysql`, `pgsql`, or `mongo` (case-insensitive), which is how the standard server
socket names are recognised. The wire protocol is identical either way, so a
local client over `/var/run` is captured and refused on the same path as a remote
one. Outside it: a server on a **non-standard TCP port**, a unix socket under a
name carrying none of those tokens, and an **abstract** socket (a leading NUL, so
the address carries no filesystem name at all). What is proven end-to-end is the
socket registration and the block path, both against a synthetic server speaking
real MySQL framing; **AgentKnox has not been verified end-to-end against a real
MySQL, PostgreSQL, or MongoDB server.**

**The in-kernel query matcher is bounded and has known false positives.** The
outbound payload is read into a per-CPU scratch buffer **bounded by the payload's
own length** and zeroed first. (A fixed-size read faulted in its entirety when a
short query ended near a page boundary, and a check that treats an unreadable
payload as nothing to block would have let a denied query through on its buffer
placement alone; that is now closed and tested.) The matcher lowercases 64 bytes
of the payload and anchors each candidate on a preceding SQL delimiter — space,
tab, newline, carriage return, backtick, dot, opening parenthesis, or comma —
which is what makes `FROM\tusers`, ``FROM `users` ``, `FROM db.users`,
`FROM (users)`, and `FROM p, users` match while `'users'` inside a literal does
not. The scan reaches as far as the denied name's own length permits, so for a
five-byte table name the name must **begin within the first 55 bytes of the
statement**; a longer name has a correspondingly shorter reach, and a reference
past the window is not matched. Known false positives remain: a column, an alias,
a quoted literal, or a longer identifier that has the denied name as its prefix
all match too. The userspace parser reclassifies afterwards, so the alert is
corrected even though the send was already refused.

**Bootstrap windows.** The session root pid is registered by userspace after
detection; anything forked or exec'd in that sub-second window before registration
is missed. Semantic uprobes likewise attach a moment after detection. In-kernel
arming at `bprm` and `execve` and fork inheritance shrink this window but do not
eliminate it.

**DNS parsing coverage.** `fqdn:` rules are enforced by parsing DNS answers
captured at the UDP port-53 `recvfrom` / `recvmsg` boundary, on unconnected and
connected resolver sockets alike. TCP DNS, DoH, and DoT resolutions are not
parsed, so a name resolved over those paths does not feed the dynamic IP deny set.
CIDR rules and the deny-egress posture are unaffected.

**Connection-granularity enforcement for IPv6 and TLS-wrapped databases.** IPv6
egress and a database connection carried inside TLS are enforced at **connection
granularity** — by address or prefix at `connect` — not by content: there is no
per-query decision for a database connection whose wire bytes never appear as
plaintext on a registered socket.

**Persistence heuristic coverage.** The persistence-path list is curated
(cron, systemd, at, hooks, rc files, autostart). Novel or relocated auto-exec
locations outside the list are not tainted.

**Non-attachable TLS for remote MCP.** A remote MCP client using a stack the
resolver cannot reach ([§6](#6-residual-limits--fundamental)) is semantically
blind, though a stdio child server's effects remain visible at the system layer.

---

## 6. Residual limits — fundamental

Not closable by more engineering at this boundary; they define the ceiling of
transparent, same-host monitoring.

**In-process TLS beyond the SSL boundary.** The resolver prefers an
`SSL_read`/`SSL_write`-shaped boundary. Go's `crypto/tls` is covered through its
retained symbols, and stripped rustls/aws-lc-rs through its byte-stable AEAD
assembly. But the AEAD boundary yields decrypted **records**, not application
messages: Codex's transport is a permessage-deflate WebSocket whose frames are
decodable only when the intermittent AEAD capture is complete, so its content
comes from the on-disk session transcript instead. Such a boundary attaches
cleanly and still yields no usable plaintext, which is precisely the case coverage
reports as `degraded`. Coverage is therefore decided by what the boundary delivers
at runtime, not by what the attach plan reached: a session graded `full` is
re-checked after a 45-second grace period (longer than a cold agent's first model
round trip) and demoted to `degraded` if no semantic event arrived from the live
boundary. Content sourced from a transcript never counts as `full`. An agent that
uses a non-attachable stack **and** keeps no local transcript is the residual
case, and its coverage is reported as `none`.

**Pure-data confused deputy.** If the agent produces no new executable and no
descendant, and only feeds **data** to an existing trusted process that then acts
(appending to a file an existing cron already runs, posting to a running service's
socket), there is no new taint target and no tree membership to attribute. This is
the general data/code-separation problem.

**Covert and side channels.** Timing, resource, and other non-syscall channels are
out of scope for a syscall- and plaintext-boundary monitor.

**Kernel prerequisites.** Pre-operation enforcement needs `bpf` in the active LSM
list and a BTF-enabled 5.15+ kernel. Without BPF-LSM the userspace backend cannot
pre-block: `Block` decisions degrade to alerts, and only `Kill` enforces, by
post-hoc `SIGKILL` of the offending process or session.

---

## 7. Agent privilege

The adversary is an agent acting through its tool surface, not a kernel-level
attacker writing exploits. That draws one line, and it is not the line one might
expect.

- **Mediation is privilege-independent.** A session member's ordinary operations
  are mediated whatever uid it runs as, including `root`, because the LSM hooks
  key on session membership. Running the agent as `root` does not exempt it.
- **In model.** An agent that tries to `SIGKILL` or ptrace the daemon, or to
  overwrite, truncate, or delete its policy directory or audit log, is doing an
  anomalous *tool-surface* action, and AgentKnox denies it in the kernel.
- **Out of model.** An agent granted `CAP_BPF` or `CAP_SYS_ADMIN` could detach or
  unload the BPF programs and tear the monitor down. That is not an agent misusing
  its tools; it is an attack on the enforcement mechanism itself, and AgentKnox
  does not claim to defeat it.

The deployment consequence is narrow and specific: **withhold `CAP_BPF` and
`CAP_SYS_ADMIN` from the agent**, and run AgentKnox with them. Nothing else about
the agent's privileges needs to change for the enforcement envelope to hold.

---

## 8. Design stance

AgentKnox controls what an AI coding agent does on a developer host, at session
granularity, without modifying the agent. Its guarantees are:

1. Transparent observation and pre-operation enforcement of the common direct
   paths — exec, file, network, signals, database sends — in the kernel.
2. Causal attribution across the agent's process tree, robust to reparenting,
   daemonization, and delayed out-of-tree execution.
3. Semantic capture at **both** the TLS boundary and the stdio pipe boundary, so a
   locally spawned MCP server is not a blind spot.
4. Honest reporting of degraded and absent coverage, decided from what the
   boundary actually delivered.

An unresolvable path, a rejected deny-egress arm, and a rejected session-membership
write at exec all refuse the operation rather than trading the fault for an allow.
The two faults that do not refuse (`taint_store`, `db_read`) are named in
[§3](#3-failure-behaviour-of-the-kernel-hooks) rather than left to be discovered.
The residual limits — non-attachable TLS stacks, unlabelled pipe content, a
path-keyed code taint, a bounded query matcher, and pure-data deputies — are
stated rather than hidden, and they bound what any transparent, same-host monitor
can promise.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
