---
name: Feature request
about: Suggest an enhancement for AgentKnox
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

<!-- SPDX-License-Identifier: Apache-2.0 -->

## Problem Statement
<!-- What are you trying to achieve? What threat, gap, or blind spot does this address? -->

## Proposed Solution
<!-- What should AgentKnox do? -->

## Affected Layer
<!-- Which part of the system would change? -->
- [ ] Semantic capture (TLS boundary, stdio MCP, database wire, transcripts)
- [ ] System capture (BPF-LSM hooks, tracepoints, wire format)
- [ ] Session detection and attribution
- [ ] Correlation (intent-effect join, taint)
- [ ] Policy schema or engine
- [ ] Enforcement (kernel push-down, userspace fallback)
- [ ] Export, WAL, aggregator, or `akctl`
- [ ] Packaging and deployment

## Use Cases
<!-- Concrete scenarios where this would matter -->
1. 
2. 
3. 

## Alternatives Considered
<!-- Including whether an existing policy predicate already covers this -->

## Implementation Notes
<!-- Any specific implementation ideas, and whether it needs kernel-side work -->

## Additional Context
<!-- Related work, agent behavior, or prior discussion (see docs/) -->

## Checklist
- [ ] I have searched the existing issues
- [ ] I have checked [docs/threat-model.md](../../docs/threat-model.md) to confirm this is not a documented out-of-scope limit
- [ ] I have provided a clear problem statement and use cases
- [ ] I have considered alternatives
