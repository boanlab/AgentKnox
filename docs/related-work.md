<!-- SPDX-License-Identifier: Apache-2.0 -->
# Related Work

This document places AgentKnox against adjacent research systems and production
tools, so a reader can decide which one fits their problem. It states what each
approach does and where it applies, including the cases where another tool is the
better choice. What AgentKnox itself defends, and what it does not, is in
[threat-model.md](threat-model.md).

---

## Table of Contents

- [The landscape](#the-landscape)
- [Capability comparison](#capability-comparison)
- [Closest related systems](#closest-related-systems)
- [Where other tools fit better](#where-other-tools-fit-better)
- [References](#references)

---

## The landscape

Defenses for LLM agents cluster into five layers by where they intervene.

| Layer | Examples | Intervenes at | Sees system effects | Constraint for monitoring a shipped coding agent |
|---|---|---|---|---|
| Prompt / content filtering | LlamaFirewall [[1]](#references), NeMo Guardrails [[2]](#references) | Text | No | Must be embedded in the agent; observes the text, not the resulting behavior |
| Tool and API guarding | Progent [[3]](#references), AgentSpec [[4]](#references), GuardAgent [[5]](#references), Conseca [[6]](#references), and the agents' own permission systems (Claude Code hooks, Codex approvals) | The tool call | No | A `bash` call is opaque at that layer; child processes and indirect effects are not visible, and the hook is cooperative |
| Architecture / information flow | CaMeL [[7]](#references), FIDES [[8]](#references), IsolateGPT [[9]](#references), AirGapAgent [[10]](#references) | By construction | Partial | Requires building or rewriting the agent; cannot be retrofitted to a shipped CLI |
| OS isolation and syscall monitoring | Falco [[11]](#references), Tetragon [[12]](#references), Tracee [[13]](#references), KubeArmor [[14]](#references), gVisor [[15]](#references), E2B [[16]](#references), Anthropic sandbox-runtime [[17]](#references) | Isolation, or a syscall decision | Yes | No semantic context: "running the test suite" and "exfiltrating `.env`" present the same syscalls |
| Semantic plus kernel | AgentSight [[18]](#references), ActPlane [[19]](#references), AgentKnox | Both | Yes | See below |

---

## Capability comparison

Entries describe what each system's published design does, not a benchmark.

| Capability | Prompt / tool guardrails | Hook and proxy enforcers (Cupcake [[20]](#references), Invariant [[21]](#references)) | Sandboxes | eBPF runtime security | AgentSight | ActPlane | AgentKnox |
|---|---|---|---|---|---|---|---|
| Prompt / response / `tool_use` capture | Partial, embedded | Hook or proxy | No | No | Yes, at TLS | No | Yes, at TLS |
| File / process / network capture | No | Requests only | Isolation only | Yes | Yes | Yes | Yes |
| Causal semantic-to-system correlation | No | No | No | No | Yes | Partial | Yes |
| Enforcement point | In-agent | Cooperative hook or proxy | Isolation boundary | Kernel | None (observation) | Kernel | Kernel |
| Provenance-based execution control | No | No | No | No | No | IFC labels | Kernel write taint under path hash and inode |
| Works on unmodified, shipped agents | No | Partial | Per process | Yes | Yes | Partial | Yes |
| MCP semantics over remote TLS **and** local stdio pipes | Partial | Hook | No | No | TLS | No | Both |
| Attribution across reparenting and delayed execution | n/a | n/a | Per process | cgroup or lineage | Lineage | Lineage | Fork-time kernel tag plus persistence attribution |
| Monitor self-integrity against the monitored agent | n/a | No | n/a | No | n/a (observation) | Policy is agent-declared | `task_kill`, `ptrace`, and policy-tamper denied in the kernel |
| Database wire parsing | No | No | No | No | No | No | PostgreSQL, MySQL, MongoDB |

---

## Closest related systems

**AgentSight** [[18]](#references) is the nearest prior system that links agent
semantics to OS behavior across agents, and it is where AgentKnox starts. It
introduces *boundary tracing*: eBPF uprobes lift TLS-encrypted LLM traffic as
plaintext, kernel events are collected in parallel, and the two are causally
correlated, with a reported overhead below 3%. It is positioned as an
observability framework. AgentKnox differs in three respects: enforcement happens
in the kernel before the operation rather than being reported after it; capture
also covers the stdio pipe boundary, which matters because a locally spawned MCP
server (filesystem, git) speaks JSON-RPC over pipes and never crosses TLS at all;
and policy is a rule language spanning both layers rather than an event stream.

**ActPlane** [[19]](#references) enforces agent-harness policies in the OS kernel
with eBPF and carries an information-flow-control DSL for cross-event policies,
reporting 1.9–8.4% overhead and improved compliance on indirect execution paths
that tool-call interception cannot observe. Its policy context comes from the
agent's own declaration rather than from a captured model stream, so the LLM's
intent is not itself an input to the decision, and the policy originates with the
process being constrained. AgentKnox instead recovers the intent from the model
traffic, owns the policy outside the agent, and denies the session write access to
its own binary, config, and policy directory. Both systems use taint; AgentKnox's
is content-agnostic and set in the kernel on the write-open under both the path
hash and the inode, so a rename or hard link does not produce an executable alias.
Its limits are equally concrete: the narrower code label that gates an
interpreter's read is path-keyed when derived in userspace, and content that never
becomes a file is not labelled at all
([threat-model.md §5](threat-model.md#5-residual-limits--engineering-remaining)).

---

## Where other tools fit better

- **Prompt guardrails** ([[1]](#references), [[2]](#references)) use model-internal
  signals — classifiers, alignment checks, static analysis of generated code — to
  catch prompt injection in the text itself. AgentKnox sees the plaintext at the
  boundary but delegates that judgement to policy; it does not classify text.
- **Isolation runtimes** ([[15]](#references), [[16]](#references),
  [[17]](#references)) contain blast radius by shrinking the reachable kernel
  surface or the reachable filesystem and network. AgentKnox does not contain; it
  observes and enforces policy. The two compose: run AgentKnox alongside a sandbox.
- **IFC-by-construction designs** ([[7]](#references), [[8]](#references)) give
  stronger information-flow guarantees, at the cost of building or rewriting the
  agent. AgentKnox gives up part of that guarantee in exchange for working on
  agents as shipped.
- **General-purpose runtime security** ([[11]](#references)–[[14]](#references))
  has mature rule ecosystems, Kubernetes integration, and large-scale operational
  track records. AgentKnox is a narrow tool for coding agents on developer hosts,
  not a general-purpose HIDS. Its sibling project
  [KloudKnox](https://github.com/boanlab/KloudKnox) is the cluster-oriented system
  from the same lab.
- **Hook and proxy enforcers** ([[20]](#references), [[21]](#references)) integrate
  with an agent's own extension points and can therefore reason about a tool call
  before it is dispatched, including with a policy language and an LLM judge.
  AgentKnox sees the same call only as plaintext on the wire, and it enforces
  below the agent instead of inside it.

---

## References

1. Chennabasappa et al. *LlamaFirewall: An open source guardrail system for building secure AI agents.* [arXiv:2505.03574](https://arxiv.org/abs/2505.03574).
2. NVIDIA. *NeMo Guardrails.* https://github.com/NVIDIA/NeMo-Guardrails
3. Shi et al. *Progent: Programmable Privilege Control for LLM Agents.* [arXiv:2504.11703](https://arxiv.org/abs/2504.11703).
4. Wang et al. *AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents.* [arXiv:2503.18666](https://arxiv.org/abs/2503.18666).
5. Xiang et al. *GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning.* [arXiv:2406.09187](https://arxiv.org/abs/2406.09187).
6. Tsai and Bagdasarian. *Contextual Agent Security: A Policy for Every Purpose.* HotOS 2025. [arXiv:2501.17070](https://arxiv.org/abs/2501.17070).
7. Debenedetti et al. *Defeating Prompt Injections by Design* (CaMeL). [arXiv:2503.18813](https://arxiv.org/abs/2503.18813).
8. Costa, Köpf et al. *Securing AI Agents with Information-Flow Control* (FIDES). [arXiv:2505.23643](https://arxiv.org/abs/2505.23643) · https://github.com/microsoft/fides
9. Wu et al. *IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems.* NDSS 2025. [arXiv:2403.04960](https://arxiv.org/abs/2403.04960).
10. Bagdasarian et al. *AirGapAgent: Protecting Privacy-Conscious Conversational Agents.* [arXiv:2405.05175](https://arxiv.org/abs/2405.05175).
11. Falco. https://falco.org
12. Cilium Tetragon. https://github.com/cilium/tetragon
13. Aqua Tracee. https://github.com/aquasecurity/tracee
14. KubeArmor. https://kubearmor.io
15. gVisor. https://gvisor.dev
16. E2B. https://e2b.dev
17. Anthropic. *sandbox-runtime.* https://github.com/anthropic-experimental/sandbox-runtime
18. Zheng et al. *AgentSight: System-Level Observability for AI Agents Using eBPF.* [arXiv:2508.02736](https://arxiv.org/abs/2508.02736) · https://github.com/agent-sight/agentsight
19. *ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses.* [arXiv:2606.25189](https://arxiv.org/abs/2606.25189) · https://github.com/eunomia-bpf/ActPlane
20. EQTY Lab. *Cupcake — a policy enforcement layer for AI coding agents.* https://github.com/eqtylab/cupcake
21. Invariant Labs. *Guardrails and Gateway.* https://explorer.invariantlabs.ai/docs/guardrails/gateway/

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
