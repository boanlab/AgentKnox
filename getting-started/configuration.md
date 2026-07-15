<!-- SPDX-License-Identifier: Apache-2.0 -->
# Configuring AgentKnox

Two things are configured: the **daemon** (`agentknox.yaml`) and the **policies** (`AgentKnoxPolicy` YAML files). This document is the full reference for both: every key, every predicate field, every effect, and every validation rule.

For installing and running, see [installation.md](installation.md) and [quickstart.md](quickstart.md). For symptom-indexed diagnostics, see [troubleshooting.md](troubleshooting.md).

---

## Table of Contents

- [Daemon Configuration](#daemon-configuration)
  - [Where config comes from](#where-config-comes-from)
  - [Config keys](#config-keys)
  - [enforcerBackend](#enforcerbackend)
  - [dryRun](#dryrun)
  - [manageCgroup](#managecgroup)
  - [Example agentknox.yaml](#example-agentknoxyaml)
- [Policy Schema](#policy-schema)
  - [Document structure](#document-structure)
  - [Selector](#selector)
  - [Rule predicates: when.semantic](#rule-predicates-whensemantic)
  - [Rule predicates: when.system](#rule-predicates-whensystem)
  - [Rule predicates: when.condition](#rule-predicates-whencondition)
  - [Effects](#effects)
  - [What gets pre-enforced in the kernel](#what-gets-pre-enforced-in-the-kernel)
  - [Validation rules](#validation-rules)
  - [Example: the shipped policy](#example-the-shipped-policy)
  - [The provenance-taint pattern](#the-provenance-taint-pattern)
- [See also](#see-also)

---

## Daemon Configuration

### Where config comes from

Configuration is resolved in this order, later overriding earlier:

1. Built-in **defaults** (the table below).
2. `agentknox.yaml` found in the working directory (`.`) **or** `/etc/agentknox/`.
3. `AGENTKNOX_<KEY>` **environment variables**, for example `AGENTKNOX_LOGLEVEL=debug`.

The config file is optional; with none present the defaults apply. `--log-level` on the command line is the one flag that overrides the resolved `logLevel`.

Only `aggregatorAddr` is hot-reloaded. The daemon watches the directory holding the resolved config file and re-reads it on change, but applies only the aggregator target without a restart; every other key takes effect at startup.

### Config keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | string | `workstation` | Deployment context (informational): `workstation` (systemd daemon on the host), `docker` (privileged host container), `host` (CLI only, dev/test). Agents always run natively on the host and policies are always local YAML. |
| `nodeName` | string | *hostname* (`localhost` if unknown) | Node identity stamped onto forwarded events. |
| `policyDir` | string | `/etc/agentknox/policies` | Directory scanned at startup for `*.yaml` policy files, and watched for changes. A missing directory means observe-only. |
| `grpcAddr` | string | `:36920` | Listen address for the `AgentKnoxExport` gRPC service and the standard gRPC health service. `akctl` connects here. |
| `aggregatorAddr` | string | *(empty)* | gRPC target (`host:port`) of a central [aggregator](aggregator.md) to forward events to. Empty disables forwarding. **Hot-reloaded.** |
| `walDir` | string | `/var/lib/agentknox/wal` | Directory for the durable JSONL write-ahead log of events and decisions. |
| `archiveDir` | string | `/var/lib/agentknox/scripts` | Where scripts and code that an agent writes and then runs are copied for forensics. |
| `semanticEnabled` | bool | `true` | Enable the semantic layer. `false` disables both TLS-boundary capture and the transcript readers, leaving syscall-only operation. |
| `capturePrompts` | bool | `true` | Capture raw prompt and response bodies (stored **locally** in the WAL). `false` replaces the text with a `<redacted:N chars>` placeholder and drops `tool_use` inputs. |
| `offsetDBPath` | string | `/etc/agentknox/offsetdb` | Build-id → TLS offset database consulted by the attach resolver. A `signatures.json` in the **same directory** supplies prologue signatures. See [semantic-coverage.md](semantic-coverage.md). |
| `agentSignatures` | []string | `["claude","codex","crush","gemini","copilot"]` | Program-name signatures used to detect agent processes. Add your own launcher name if it differs. |
| `cgroupParent` | string | `agentknox.slice` | The managed cgroup v2 slice sessions are placed under when `manageCgroup` is enabled. |
| `manageCgroup` | bool | `false` | `false` (non-invasive) keys sessions by their existing cgroup id and scopes enforcement to the agent's pid tree. `true` **moves** detected agents into a dedicated managed cgroup. |
| `enforcerBackend` | string | `auto` | `auto`, `bpf-lsm`, or `userspace` (alias `apparmor`). See below. |
| `dryRun` | bool | `false` | `true` observes only and never applies a `Block` or `Kill` to the kernel. |
| `logLevel` | string | `info` | `debug`, `info`, `warn`, or `error`. Also settable with `--log-level`. |

#### enforcerBackend

- `auto` (default): use the **BPF-LSM** backend (in-kernel pre-block) when `bpf` is in `/sys/kernel/security/lsm`, otherwise the **userspace** backend.
- `bpf-lsm`: force BPF-LSM. If `bpf` is not in the LSM list, the attach will likely fail.
- `userspace` (alias `apparmor`): force the userspace backend. It cannot pre-block in the kernel, so its repertoire is **alert plus kill**: a `Kill` verdict sends `SIGKILL` to the offending process or session after the fact, and a `Block` verdict degrades to an alert because the operation has already occurred.

The choice is made from the LSM list *before* the programs are attached, which cannot foresee a hook the kernel then declines. The daemon therefore re-checks after attach: `file_open`, `bprm_check_security`, and `socket_connect` are the **core** hooks the pre-operation guarantee rests on. If any of them fails to attach, the daemon logs `core BPF-LSM hooks unavailable` and demotes itself to the userspace backend rather than installing kernel rules that nothing would read. Losing any other hook costs exactly one operation, which is logged and left observed rather than refused.

#### dryRun

With `dryRun: true` the daemon evaluates policy and emits alerts as usual, but the enforcer never applies a `Block` or `Kill` decision. Kernel rule entries are still written into the BPF maps; they take effect only for a session that also carries the enforce flag, and in dry-run mode no session is ever given that flag. Run this way to validate a new policy before letting it act.

#### manageCgroup

By default AgentKnox does not move any process. It keys the session on the cgroup the agent is already in and scopes enforcement to the agent's pid tree, so a co-resident process that happens to share that cgroup is not affected. Setting `manageCgroup: true` moves the detected agent's process tree into a dedicated slice under `cgroupParent`, which gives a cleaner enforcement key at the cost of being invasive to a live process tree.

### Example agentknox.yaml

This is the shipped `deployments/agentknox.yaml`, showing every key at its default:

```yaml
# SPDX-License-Identifier: Apache-2.0
# Place at ./agentknox.yaml or /etc/agentknox/agentknox.yaml.
# Every key can also be overridden by AGENTKNOX_<KEY> env vars.
mode: workstation                 # workstation | docker | host
policyDir: /etc/agentknox/policies
grpcAddr: ":36920"                # AgentKnoxExport gRPC service listen address
manageCgroup: false               # true = move agents into dedicated cgroup (invasive)
walDir: /var/lib/agentknox/wal
archiveDir: /var/lib/agentknox/scripts   # scripts/code the agent writes & runs are copied here
semanticEnabled: true
capturePrompts: true              # true = capture raw prompt/response bodies (stored locally in WAL)
offsetDBPath: /etc/agentknox/offsetdb
agentSignatures: ["claude", "codex", "crush", "gemini", "copilot"]
cgroupParent: agentknox.slice
enforcerBackend: auto             # auto | bpf-lsm | userspace
dryRun: false                     # true = observe, never block/kill
logLevel: info
# aggregatorAddr: aggregator-host:36930   # forward events to a central aggregator over gRPC
#                                         # (hot-reloaded: edit this line, no daemon restart)
```

---

## Policy Schema

Policies are declarative YAML documents with `kind: AgentKnoxPolicy`. The daemon loads every `*.yaml` under `policyDir`, validates and compiles them, and installs the pre-enforceable subset into the kernel. The schema is shared by the daemon and `akctl` and is defined in [`../pkg/policyspec/policyspec.go`](../pkg/policyspec/policyspec.go).

> Policies **hot-reload**: the daemon watches `policyDir` with fsnotify and recompiles on change. A malformed file is logged with `policy load` and skipped, and the previously valid rule set stays in force.

### Document structure

```yaml
apiVersion: security.boanlab.com/v1   # informational, not validated
kind: AgentKnoxPolicy                 # required, must be exactly this
metadata:
  name: <policy-name>                 # required
spec:
  selector: ["*"]                     # required; agent kinds this policy applies to
  defaultEffect: Allow                # optional; effect when no rule matches (default: Allow)
  rules:
    - name: <rule-name>               # required per rule
      when:                           # the predicate (see below)
        semantic: { ... }             # at least one of semantic / system is required
        system:   { ... }
        condition: { ... }            # optional gate
      effect: Block                   # required per rule
```

| Field | Meaning |
|---|---|
| `spec.selector` | List of agent kinds this policy governs. Must be non-empty. |
| `spec.defaultEffect` | Effect applied when no rule matches. Defaults to `Allow`. |
| `spec.rules[]` | Ordered list of `when → effect` rules. **The first matching rule wins**, in the order the rules were loaded, so put the more specific rule first. |

Rules from every policy file are concatenated in load order. Where several policy files set `spec.defaultEffect`, the **strongest** of them becomes the daemon-wide default (`Allow` < `Audit` < `Alert` < `Block` < `Kill`).

### Selector

`spec.selector` matches the normalized agent kind, not the binary name:

| Value | Matches |
|---|---|
| `claude-code` | Claude Code |
| `codex` | OpenAI Codex CLI |
| `crush` | Crush |
| `gemini` | Gemini CLI |
| `copilot` | GitHub Copilot CLI |
| `*` | every agent |

### Rule predicates: `when.semantic`

Matches the semantic layer: the model's intent, MCP traffic, and parsed database queries.

| Field | Meaning / values |
|---|---|
| `tool` | Tool name of a `tool_use`, for example `Bash` or `Read`. Glob metacharacters (`*?[`) are honored. |
| `mcpMethod` | MCP JSON-RPC method, for example `tools/call`. Glob-aware. |
| `provider` | Source label of the semantic event, matched case-insensitively. Live-boundary events carry `anthropic` or `openai`; transcript-sourced events carry their reader's label (`codex-rollout`, `claude-transcript`, `gemini-transcript`, `copilot-transcript`, `crush-transcript`), and the agent's launch command line is indexed as `argv`. |
| `intentClass` | Coarse intent derived from the tool name: `read`, `write`, `network`, or `exec`. |
| `taint` | Requires the effect to carry this **correlation label**, attached in userspace when the correlator joins an effect to the session's history: `user-unseen`, `sensitive`, or `data-flow`. |
| `provenance` | Requires the file to carry this **provenance label**: `agent-written` or `agent-code`. |
| `dbEngine` | Database engine of a parsed query: `postgres`, `mysql`, or `mongodb`. Matched case-insensitively. |
| `dbTable` | Table or collection name. Glob-aware. |
| `dbOp` | Query operation, for example `SELECT`, `INSERT`, or `find`. Matched case-insensitively. |

> The three `db*` fields live under **`when.semantic`**, not `when.system`. A parsed query's engine, table, and operation are content lifted from the plaintext wire, which the syscall stream cannot express. The system layer sees only the endpoint of that connection.

**`taint` and `provenance` are different label families and are not interchangeable.** `taint` answers what an effect *means* to the correlator; `provenance` answers which principal *produced a file*, and is recorded in the kernel. Spelling a provenance label under `taint` is rejected at load, as is an unknown provenance label.

`agent-written` is recorded in the kernel on the write-open, under both the path and the inode, and is enforced at `exec`. `agent-code` additionally gates an interpreter's read of the file; it is inode-backed only when the file was already executable at write time, and otherwise derived by the daemon from a shebang, the extension, or a later `chmod` and stored under the path alone. See [`../docs/threat-model.md`](../docs/threat-model.md).

### Rule predicates: `when.system`

Matches the system layer: the operation the kernel actually observed.

| Field | Meaning / values |
|---|---|
| `op` | Operation: `exec`, `open`, `read`, `write`, `connect`, `query`, `delete`, `rename`, `chmod`, `chown`. Syscall variants are normalized first (`openat`→`open`, `pwritev`→`write`, `sendto`/`sendmsg`→`connect`, and so on). |
| `path` | File path, matched with `path.Match`, so `*` and `?` work. Only a **concrete absolute path with no wildcard** can be pre-installed in the kernel. |
| `dir` | Directory prefix. A missing trailing `/` is added. |
| `cidr` | Network CIDR for `connect`. Compiled into the kernel egress deny map (an LPM trie) for pre-blocking, IPv4 and IPv6. |
| `fqdn` | Domain name for `connect`, matched as a suffix of the resource. A `Block` rule is enforced dynamically: captured DNS answers whose name matches install the resolved IPs into the kernel egress deny map, evicted when their TTL lapses. Only UDP port-53 answers are parsed, so TCP DNS, DoH, and DoT resolutions do not feed the deny set. |

Two notes on `op`:

- `op: write` also covers `truncate`, because the `security_path_truncate` hook checks the write bit. A path already write-protected needs no extra rule.
- `op: query` matches the *endpoint* of a database connection, so it composes with a `when.semantic` `dbTable` predicate to say "this table, over this connection".

### Rule predicates: `when.condition`

Temporal and session-state gates. A condition is evaluated in userspace, so a rule that carries one is never pre-installed in the kernel.

| Field | Meaning |
|---|---|
| `after` | Match only after an earlier marker occurred in this session: an intent class (`read`, `write`, `network`, `exec`) or a syscall op (`connect`, `open`, …). |
| `within` | Bounds `after`: the marker must have occurred within this window, as a Go duration such as `5s`. |
| `sessionState` | Match a session lifecycle state: `active` or `ended`. |
| `coverage` | Match semantic coverage: `full`, `degraded`, or `none`. Lets a policy tighten posture exactly when semantic observability is lost. A session whose boundary attached but never delivered live plaintext is downgraded to `degraded` at runtime, so this matches the sessions AgentKnox is actually blind on, not the ones whose attach plan merely looked complete. |
| `tampered` | `true` or `false`. Matches the session's binary-identity flag, decided for every resolved binary regardless of which resolver tier served it. Set when a loaded known-good reference set does not vouch for the build-id, **or** when the binary's code section matches one already resolved under a different build-id. Neither fires when nothing was available to vouch for the binary at all. Omitting the key ignores the flag; it is not read as `false`. |

### Effects

| Effect | Behavior |
|---|---|
| `Allow` | Explicitly permit, overriding a stricter default posture. |
| `Audit` | Record the activity without blocking. A syscall-layer `Audit` is exported as an event only; a semantic-layer `Audit` also raises an alert. |
| `Alert` | Raise an alert; do not block. |
| `Block` | Deny the operation and alert. Pre-operation `EPERM` in BPF-LSM where the predicate is pre-installable, post-hoc otherwise. |
| `Kill` | Terminate the offending process or session and alert. A semantic-layer `Block` or `Kill` additionally arms a deny-egress posture for the session, so a follow-on connection is pre-blocked. |

Under `dryRun: true` no effect is applied to the kernel. Under the userspace backend a `Block` degrades to an alert while `Kill` still terminates; see [enforcerBackend](#enforcerbackend).

### What gets pre-enforced in the kernel

Understanding which rules become kernel map entries explains why some blocks are pre-operation and others are post-hoc.

| Rule shape | Pre-installed? |
|---|---|
| `effect: Block`, `when.system` only, `op` in `open`/`read`/`write`/`exec`/`delete`/`rename`/`chmod`/`chown`, `path` an exact absolute path or `dir` a prefix | **Yes** — an entry in the file or directory map |
| `effect: Block`, `when.system` only, `op: connect` with a `cidr` | **Yes** — an entry in the IPv4/IPv6 LPM egress deny map |
| `effect: Block` with `when.semantic.dbTable` | **Yes** — the denied table is pushed down, and a matching outbound query is refused before it reaches the server |
| `effect: Block`, `op: connect` with only an `fqdn` | **Dynamically** — resolved IPs are installed as captured DNS answers arrive, and evicted on TTL expiry |
| Anything carrying a `when.condition` | No — session and history state lives in userspace, and enforcing without the condition would be stricter than asked |
| Any other rule (a semantic predicate, a wildcard path, `Alert`/`Audit`/`Kill`) | No — evaluated in userspace and applied post-hoc |

A rule the kernel refuses (a full map, a malformed CIDR) does not abandon the rules after it: every rule is attempted, so which rules are enforced never depends on their order in the policy file. Drops are counted per map and logged at `Error`; see [troubleshooting.md](troubleshooting.md#kernel-rule-set-is-incomplete).

### Validation rules

A policy file is rejected, logged with `policy load`, and skipped if:

| Condition | Message |
|---|---|
| `kind` is not exactly `AgentKnoxPolicy` | `kind must be AgentKnoxPolicy, got "..."` |
| `metadata.name` is empty | `metadata.name required` |
| `spec.selector` is empty | `spec.selector required (use ["*"] for all agents)` |
| `spec.defaultEffect` is set but not a valid effect | `invalid defaultEffect "..."` |
| A rule is missing `name` | `rule[N].name required` |
| A rule's `effect` is not one of `Allow Audit Alert Block Kill` | `rule "...": invalid effect "..."` |
| A rule has neither `when.semantic` nor `when.system` | `rule "...": at least one of when.semantic/when.system required` |
| A provenance label is spelled under `taint` | `rule "...": "..." is a provenance label; use when.semantic.provenance, not taint` |
| `provenance` is set to something other than `agent-written`/`agent-code` | `rule "...": invalid provenance "..." (want agent-written or agent-code)` |

One error is raised later, at compile time rather than per file, and it is more disruptive: a malformed `when.system.cidr` fails the whole compile with `policy compile … invalid cidr "..."`, so **no** policy takes effect and the previous rule set stays in force. Validate a CIDR before saving the file.

### Example: the shipped policy

`deployments/policies/example.yaml` demonstrates the seven representative rule shapes:

```yaml
# SPDX-License-Identifier: Apache-2.0
apiVersion: security.boanlab.com/v1
kind: AgentKnoxPolicy
metadata:
  name: baseline-credential-protection
spec:
  selector: ["*"] # claude-code | codex | crush | gemini | copilot | *
  defaultEffect: Allow
  rules:
    # 1. Pure system rule (pre-enforceable in BPF-LSM): never open an SSH private key.
    - name: deny-ssh-private-key
      when:
        system:
          op: open
          path: "/root/.ssh/id_rsa"
      effect: Block

    # 2. Dual-layer: a read-only tool_use that causes an outbound connection
    #    carrying a tainted, user-unseen sensitive file -> kill the session.
    - name: exfil-via-read-intent
      when:
        semantic:
          intentClass: read
          taint: sensitive
        system:
          op: connect
      effect: Kill

    # 3. Provenance: code the agent itself wrote may not be executed. Enforced in
    #    the kernel at exec, on the label the write-open recorded under both the
    #    path and the inode. Note this is when.semantic.provenance (a property of
    #    the file), not when.semantic.taint (a correlation label).
    - name: no-agent-written-code
      when:
        semantic:
          provenance: agent-written
        system:
          op: exec
      effect: Block

    # 4. Semantic only: alert on MCP tool-poisoning method probes (illustrative).
    - name: suspicious-mcp-method
      when:
        semantic:
          mcpMethod: "tools/call"
          taint: user-unseen
      effect: Alert

    # 5. FQDN egress block: DNS answers for the name are resolved to IPs and
    #    installed into the kernel egress deny map (TTL-evicted).
    - name: deny-known-bad-domain
      when:
        system:
          op: connect
          fqdn: "evil.example"
      effect: Block

    # 6. Coverage-adaptive: if semantic observability is degraded, tighten posture
    #    by alerting on any egress from such a session.
    - name: tighten-when-blind
      when:
        system:
          op: connect
        condition:
          coverage: degraded
      effect: Alert

    # 7. Identity-adaptive: the agent binary's build-id is not one the reference
    #    set vouches for, so do not let this session reach the network.
    - name: untrusted-agent-build
      when:
        system:
          op: connect
        condition:
          tampered: true
      effect: Block
```

### The provenance-taint pattern

Rules 2 and 3 above are the cases only the dual-layer fusion can express.

Rule 2 combines **`semantic.taint: sensitive`**, a correlation label the engine attaches when the agent reads data that never appeared in the user-visible prompt or response, with **`system.op: connect`**, an outbound connection observed in the kernel. It fires only when tainted, user-unseen data flows into an egress connection, that is, when a nominally read-only intent provably causes exfiltration. A string denylist cannot express it (the agent can obfuscate around the string) and an application-level hook cannot enforce it (the agent can bypass the hook).

Rule 3 is the generalized form on the provenance family: code that the agent itself wrote being executed. The label is recorded in the kernel at the write-open under both the path hash and the inode, so a rename or hard link of the file does not launder it for direct execution.

The daemon reinforces both. The instant a session becomes tainted by a read of a marked sensitive source, it arms a deny-egress posture on the session's cgroup and on the exact tainting process, so the follow-on connection is refused pre-operation even when the exfiltration is attempted from a child in a different cgroup. That arming is gated on a policy that would actually block or kill a tainted connect, so a benign read of a secret never severs a session's network access.

The end-to-end scenario these rules defend against is walked through in [`../docs/workflow.md`](../docs/workflow.md).

---

## See also

- [installation.md](installation.md) — prerequisites and service install
- [quickstart.md](quickstart.md) — end-to-end first run
- [semantic-coverage.md](semantic-coverage.md) — what `coverage` and `tampered` are derived from
- [troubleshooting.md](troubleshooting.md) — symptom-indexed diagnostics
- [`../pkg/policyspec/policyspec.go`](../pkg/policyspec/policyspec.go) — the authoritative schema

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
