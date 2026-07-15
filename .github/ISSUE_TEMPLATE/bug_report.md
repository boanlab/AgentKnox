---
name: Bug report
about: Report a problem with AgentKnox
title: '[BUG] '
labels: bug
assignees: ''
---

<!-- SPDX-License-Identifier: Apache-2.0 -->

## Bug Description
<!-- A clear and concise description of what went wrong -->

## Environment
<!-- Please provide the following information -->
- AgentKnox commit (`git rev-parse --short HEAD`):
- OS: [e.g. Ubuntu 24.04]
- Kernel (`uname -r`):
- BTF present (`ls /sys/kernel/btf/vmlinux`):
- LSM list (`cat /sys/kernel/security/lsm`):  <!-- is `bpf` in it? -->
- Enforcer backend: [bpf-lsm / userspace] <!-- the daemon logs a warning when it falls back to userspace -->
- Session coverage from `akctl sessions`: [full / degraded / none]
- Agent(s) monitored and version: [Claude Code / Codex CLI / Crush / Gemini CLI / Copilot CLI]
- Deployment mode: [.deb / manual systemd / Docker / built from source]

## Steps to Reproduce
<!-- Commands, agent prompt, and the policy in effect -->
1. 
2. 
3. 

## Expected Behavior
<!-- What you expected AgentKnox to do -->

## Actual Behavior
<!-- What it actually did -->

## Policy
<!-- The rule(s) involved, or the output of `akctl policy` -->

## Logs
<!-- Relevant daemon log lines (run with `--log-level=debug`).
     Do NOT paste captured prompts or code if they are sensitive. -->

## Additional Context
<!-- `akctl diagnose`, `akctl sessions`, or `akctl alerts` output if useful -->

## Checklist
- [ ] I have searched the existing issues
- [ ] I have provided the environment information above
- [ ] I have included relevant logs, with sensitive content removed
- [ ] I have reproduced this on the latest `main`
