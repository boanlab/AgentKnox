// SPDX-License-Identifier: Apache-2.0
package types

import "time"

// PolicyEffect is the action taken when a policy rule matches.
type PolicyEffect string

const (
	EffectAllow PolicyEffect = "Allow" // permit silently
	EffectAudit PolicyEffect = "Audit" // permit + record
	EffectAlert PolicyEffect = "Alert" // permit + raise alert
	EffectBlock PolicyEffect = "Block" // deny the operation (-EPERM)
	EffectKill  PolicyEffect = "Kill"  // terminate the offending process/session
)

// EnforceMode indicates whether a decision is enforced pre-operation (kernel)
// or post-operation (userspace).
type EnforceMode string

const (
	EnforcePre  EnforceMode = "pre"  // BPF-LSM / cgroup-BPF, before syscall completes
	EnforcePost EnforceMode = "post" // userspace, after observation
)

// Decision is the Policy Engine verdict for an event or correlated action.
type Decision struct {
	Effect     PolicyEffect `json:"effect"`
	Mode       EnforceMode  `json:"mode"`
	PolicyName string       `json:"policy_name"`
	Reason     string       `json:"reason"`
	Time       time.Time    `json:"time"`
}

// Alert is an event/action that matched an active policy with a non-Allow effect,
// or a security signal (tamper, mismatch). Exported over the Alert stream.
type Alert struct {
	AlertID    string       `json:"alert_id"`
	Time       time.Time    `json:"time"`
	SessionID  string       `json:"session_id"`
	Agent      AgentKind    `json:"agent"`
	Severity   string       `json:"severity"` // info|warn|critical
	Effect     PolicyEffect `json:"effect"`
	PolicyName string       `json:"policy_name,omitempty"`
	Reason     string       `json:"reason"`

	// One of these carries the triggering context.
	Syscall  *SyscallEvent     `json:"syscall,omitempty"`
	Semantic *SemanticEvent    `json:"semantic,omitempty"`
	Action   *CorrelatedAction `json:"action,omitempty"`
}
