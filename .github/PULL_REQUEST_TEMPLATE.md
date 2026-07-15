<!-- SPDX-License-Identifier: Apache-2.0 -->
## Summary

<!-- What does this PR do, and why? One or two sentences. -->

Closes #<!-- issue number -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] eBPF program / wire-format change (BPF header and Go decoder kept byte-locked)
- [ ] Enforcement or policy-semantics change
- [ ] Refactoring (no behavior change)
- [ ] Documentation
- [ ] Build / CI

## Changes

<!-- List the key changes. Name the modified packages or subsystems. -->

-

## Testing

<!-- How was this tested? Include the commands or test names you ran. -->

- [ ] `make gofmt` passes
- [ ] `make vet` passes
- [ ] `make test` passes
- [ ] `make golangci-lint` passes
- [ ] `make gosec` passes
- [ ] SPDX headers present (Apache-2.0 for Go, GPL-2.0 for `bpf/*.c` and `bpf/*.h`)
- [ ] Manual test: <!-- describe what you ran -->

CI does not build the eBPF object or run the root-gated kernel tests. If this PR
touches `bpf/`, confirm you ran both locally on a kernel host:

- [ ] `make bpf` succeeds and the regenerated `internal/sensor/agentknox_bpfel.o` is committed in this PR
- [ ] `sudo go test ./internal/sensor/` passes (verifier and attach, not just userspace logic)
- [ ] If a BPF map or wire layout changed, `internal/bpf2frame` and `internal/enforce` were updated in lockstep and `WireSchemaVersion` was bumped
- [ ] For enforcement or policy changes: verified end to end against a live agent session, not only in unit tests

## Notes for Reviewers

<!-- Tricky logic, known limitations, open design decisions, follow-up items. -->
