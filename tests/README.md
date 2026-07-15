<!-- SPDX-License-Identifier: Apache-2.0 -->
# AgentKnox Tests

AgentKnox has three test flavors, separated by what privilege and what kernel they
need. This document says what each one covers, how to run it, and why continuous
integration runs only the first. It is written for a contributor about to change
kernel-side or enforcement code.

| | **unit** | **kernel-gated** | **integration** |
|---|---|---|---|
| Entry point | `make test` | `sudo go test ./internal/sensor/ -run Test...` | `sudo tests/integration/enforcement.sh` |
| Runtime target | Pure Go, in-process | The real BPF object, loaded and attached | The whole daemon, against a synthetic agent session |
| Privilege | None | **root** | **root** |
| Kernel requirement | None | BTF plus `bpf` in `/sys/kernel/security/lsm` (5.15+) | Same, plus `clang` and `llvm-strip` to build the object |
| BPF toolchain | Not needed (the object is committed and `go:embed`ed) | Not needed | **Needed** — the script runs `make bpf` |
| What it proves | Parsers, resolver ladder, policy evaluation, enforcement bookkeeping | Each kernel enforcement and attribution contract, driven against a live child process | Provenance and policy end to end, through the daemon's real pipeline |
| Behaviour when unavailable | — | Skips itself (`needs root`) | Exits 2 (`must run as root`) |
| Run in CI | Yes | No — skipped, not run | No |
| Side effects | None | Loads and attaches BPF programs | Writes a policy into `/etc/agentknox/policies/`, binds `:36920` |

---

## Table of Contents

- [1. Unit tests](#1-unit-tests)
- [2. Kernel-gated tests](#2-kernel-gated-tests)
- [3. Integration test](#3-integration-test)
- [4. What CI runs, and what it does not](#4-what-ci-runs-and-what-it-does-not)

---

## 1. Unit tests

Per-package Go tests that run without privilege. The eBPF object is committed and
embedded, so no BPF toolchain is required; the tests that need `CAP_BPF` or root
skip themselves.

```sh
make test        # go test ./... -count=1
```

Three groups are worth knowing about, because they guard properties that regress
silently:

| Test | Guards |
|---|---|
| `internal/resolver/identity_test.go`, `cmd/agentknox/tamper_test.go` | Binary identity is decided for **every** tier, not only for builds that descend to the offset-database rung, and silence (no reference set, no prior sighting) is not treated as a tamper signal |
| `internal/resolver/reachability_test.go` | Every signature provider shipped in `deployments/signatures.json` is actually reachable from the tier ladder, so a provider cannot become dead weight |
| `internal/sensor/faultsync_test.go` | The kernel fault-counter names match the slots the BPF object carries. A slot added in the C header without a name here would be counted in the kernel and never reported |

The remaining unit tests cover the semantic parsers (HTTP/1, HTTP/2, SSE,
WebSocket, provider payloads, MCP JSON-RPC, and the PostgreSQL, MySQL, and MongoDB
wire formats), the resolver's tier ladder and prologue matcher, the policy engine
including its temporal `after` / `within` predicates, the enforcement bookkeeping
(including that an overflowing map does not abandon the remaining rules), the
exporter and WAL, the forwarder, the aggregator stores, and the session manager.

The aggregator's PostgreSQL store test only runs when `AGENTKNOX_TEST_PG_DSN` is
set; otherwise it skips.

---

## 2. Kernel-gated tests

`internal/sensor/enforcement_kernel_test.go` loads the real BPF object, attaches
the tracepoint and BPF-LSM programs, and drives a child process against them. Each
test asserts one kernel-side contract. These are the tests that actually prove the
enforcement claims in [`../docs/threat-model.md`](../docs/threat-model.md).

**Requirements:** root, a kernel with BTF (`/sys/kernel/btf/vmlinux`) and `bpf` in
`/sys/kernel/security/lsm`. Every test calls `t.Skip("needs root")` when run
unprivileged, which is why `make test` passes without them and proves nothing about
the kernel side.

```sh
# All of them
sudo -E go test ./internal/sensor/ -count=1 -v

# One contract
sudo -E go test ./internal/sensor/ -count=1 -run TestArmSessionFailsClosedWhenMapFull -v
```

Use `sudo -E` so the Go build cache and module cache stay where they are.

| Test | Contract |
|---|---|
| `TestSelfProtection` | An enforce-mode session member cannot write, delete, rename, or change the mode or owner of AgentKnox's own paths |
| `TestTruncateSelfProtection` | `truncate(2)` opens nothing, so it must be covered separately or the policy file and audit log could be zeroed past the write-open gate |
| `TestForkInheritance` | A `setsid` grandchild that reparents away is still enforced |
| `TestIPv6Egress` | A denied IPv6 prefix returns `EPERM` at `connect` |
| `TestPersistObserveOnly` | A persistence artifact is surfaced, not blocked — attribution is not a hidden deny |
| `TestLongPathEnforcement` | A directory rule still matches a target whose absolute path far exceeds the hooks' buffer |
| `TestUnresolvablePathFailsClosed` | A wholly unresolvable path is **refused** and counted, not allowed through unmediated |
| `TestRegisterPIDPreservesArmedFlags` | Registering a pid ORs its flags rather than overwriting an already-armed entry |
| `TestMemfdExecDenied` | `execveat(memfd, "", AT_EMPTY_PATH)` is refused on the absence of a path |
| `TestArmSessionFailsClosedWhenMapFull` | A full session map refuses the exec rather than running the process unarmed and invisible |
| `TestUnixSocketDBRegistered` | A unix socket named after a database server arms capture; one that names no database does not |
| `TestDBQueryBlockedPreOperation` | A query naming a denied table is refused in the sending syscall, while a permitted query on the **same** socket still completes |
| `TestDBQueryBlockedAtPageBoundary` | The same holds when the payload's last byte is the last byte of a page whose successor is unmapped — the placement a fixed-size read faults on |

`internal/session/manager_test.go` also has one root-gated case
(`TestPlaceInCgroupRoot`) that exercises real cgroup v2 placement.

Some cases skip on a missing facility rather than fail: `python3` is needed for the
IPv6, memfd, and database probes, and the map-exhaustion test skips if
`ak_session_pids` does not fill within 70,000 entries.

---

## 3. Integration test

`tests/integration/enforcement.sh` builds AgentKnox, runs the daemon against a
synthetic `crush` session, and asserts that the kernel plus the provenance policy
actually block the forbidden operations.

```sh
sudo tests/integration/enforcement.sh
```

**Requirements:** root, a kernel with BTF and `bpf` in
`/sys/kernel/security/lsm`, and `clang` + `llvm-strip` — unlike the Go tests, this
script runs `make bpf` and rebuilds the object.

What it does: writes a three-rule policy into `/etc/agentknox/policies/itest.yaml`,
starts the daemon, waits for `InstallRules complete` in its log, then runs a copy
of `bash` named `crush` (so the session detector onboards it) through nine
scenarios.

| Scenario | Expected | Mechanism exercised |
|---|---|---|
| Read a credential file | blocked | BPF-LSM `file_open`, exact-path rule |
| Delete inside a protected tree | blocked | `path_unlink`, directory-prefix rule |
| Execute a file the session wrote | blocked | `bprm`, write provenance taint |
| Copy that file, then run the copy | blocked | The copy is re-tainted on its own write-open |
| Hard-link alias | blocked | The taint is keyed on the inode, not only the path |
| Rename alias | blocked | `path_rename` moves the path-keyed taint |
| Symlink alias | blocked | Resolution reaches the tainted target |
| Extension disguise (`note.txt`, executable) | blocked | The taint is content-agnostic |
| A dynamic, never-before-seen path | blocked | No allowlist of known names is involved |

Every alias scenario exercises the **exec** path, which the content-agnostic write
taint covers under both the path hash and the inode. The narrower interpreter-read
path is *not* covered here; see
[`../docs/threat-model.md`](../docs/threat-model.md#5-residual-limits--engineering-remaining).

The exit code is non-zero if any scenario fails. Two side effects to know about:
the script writes into the system policy directory (removed on exit), and the
daemon binds the gRPC API on `:36920`, so stop any other AgentKnox instance first.

---

## 4. What CI runs, and what it does not

On every push to `main` and every pull request, `.github/workflows/ci.yml` runs one
job per quality gate, each mapped to the Makefile target that defines it so CI and
a local run enforce the same rules:

| Job | Runs |
|---|---|
| `go-fmt` | `make gofmt` |
| `go-vet` | `go build ./...`, `make vet` |
| `go-lint` | `golangci-lint` (the config uses the v2 schema, so the action must be v7 or later) |
| `go-sec` | `make gosec` |
| `go-test` | `make test` |
| `build-image` | `make build-image` — the image build needs no BPF toolchain, since the object is committed and embedded |

`.github/workflows/license.yml` separately checks the SPDX headers configured in
`.licenserc.yaml` (Apache-2.0 for Go sources, the Makefile, and the Dockerfile;
`bpf/` is GPL-2.0 and excluded there).

Two things CI deliberately does not do:

- **`make bpf` is not run.** It needs clang with a working `-target bpf` and
  `llvm-strip` on `PATH`, and that toolchain has not been verified on the
  GitHub-hosted runner image; a workflow that cannot build the object would fail
  for a reason unrelated to the change under review. The object is committed and
  embedded, so `go build`, `go vet`, and `go test` all work without it.
  Regenerating and loading the object stays a local step on a kernel host.
- **The root-gated tests are not run.** The runner is unprivileged, so they skip
  themselves and `make test` covers the userspace logic only. A green CI run
  therefore says nothing about the kernel side.

**Before sending a change that touches `bpf/`, `internal/sensor/`, or
`internal/enforce/`, run sections 2 and 3 locally on a BPF-LSM host.** CI cannot
catch a regression there.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
