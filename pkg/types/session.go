// SPDX-License-Identifier: Apache-2.0
package types

import "time"

// AgentKind is the normalized identity of a supported coding agent.
type AgentKind string

const (
	AgentClaudeCode AgentKind = "claude-code"
	AgentCodex      AgentKind = "codex"
	AgentCrush      AgentKind = "crush"
	AgentGemini     AgentKind = "gemini"
	AgentCopilot    AgentKind = "copilot"
	AgentUnknown    AgentKind = "unknown"
)

// SessionState tracks a session's lifecycle.
type SessionState string

const (
	SessionActive SessionState = "active"
	SessionEnded  SessionState = "ended"
)

// SemanticCoverage reports how well the Attach Resolver recovered the
// plaintext boundary for a session. It is both a diagnostics field and a
// first-class policy input (the `coverage` condition predicate).
type SemanticCoverage string

const (
	CoverageFull     SemanticCoverage = "full"
	CoverageDegraded SemanticCoverage = "degraded"
	CoverageNone     SemanticCoverage = "none"
)

// AgentSession is the normalized cross-agent unit of monitoring & enforcement.
// The Session Manager detects, normalizes, and manages its lifecycle.
type AgentSession struct {
	ID         string    `json:"id"` // UUIDv7
	Agent      AgentKind `json:"agent"`
	RootPID    int32     `json:"root_pid"`
	CgroupID   uint64    `json:"cgroup_id"`
	CgroupPath string    `json:"cgroup_path,omitempty"` // agentknox.slice/session-<id>

	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time,omitempty"`
	State     SessionState `json:"state"`

	Provider string  `json:"provider,omitempty"`
	Members  []int32 `json:"members,omitempty"` // host PIDs in the session tree

	// Semantic attach
	Coverage   SemanticCoverage `json:"coverage"`
	AttachPlan *AttachPlan      `json:"attach_plan,omitempty"`
	// WireIntents counts semantic events actually recovered from the live
	// plaintext boundary (not from the on-disk transcript). It is what separates
	// "attached" from "attached and yielding plaintext": a boundary can hook
	// cleanly and still deliver nothing, which is why coverage cannot be decided
	// from the attach plan alone.
	WireIntents int64 `json:"wire_intents,omitempty"`

	// Security posture
	Tainted     bool     `json:"tainted,omitempty"`
	TaintLabels []string `json:"taint_labels,omitempty"`
	Tampered    bool     `json:"tampered,omitempty"` // build-id != known-good
}

// AttachTier records which rung of the offset-recovery ladder succeeded (T1..T7).
type AttachTier string

const (
	TierDynsym       AttachTier = "T1-dynsym"
	TierSymtab       AttachTier = "T2-symtab"
	TierDebuginfod   AttachTier = "T3-debuginfod"
	TierOffsetDB     AttachTier = "T4-offsetdb"
	TierPatternMatch AttachTier = "T5-pattern"
	TierXref         AttachTier = "T6-xref"
	TierBoundaryMove AttachTier = "T7-boundary"
	TierFailed       AttachTier = "failed"
)

// BoundaryKind is the plaintext boundary the resolver selected.
type BoundaryKind string

const (
	BoundarySSL     BoundaryKind = "ssl"      // SSL_read/SSL_write (OpenSSL/BoringSSL)
	BoundaryAEAD    BoundaryKind = "aead"     // aws-lc-rs EVP_AEAD_CTX_open/seal (rustls)
	BoundaryAEADAsm BoundaryKind = "aead-asm" // CRYPTOGAMS AEAD asm (chacha/aesni-gcm, stripped rustls)
	BoundaryGoTLS   BoundaryKind = "go-tls"   // Go crypto/tls.(*Conn).Read/Write (pure-Go TLS)
	BoundaryNone    BoundaryKind = "none"
)

// AttachPlan is the output of the Semantic Attach Resolver. The Semantic
// Sensor attaches uprobes at these file offsets (func_name=NULL).
type AttachPlan struct {
	BinaryPath string           `json:"binary_path"`
	Library    string           `json:"library"` // libssl.so.3 | <self> | ...
	BuildID    string           `json:"build_id,omitempty"`
	Boundary   BoundaryKind     `json:"boundary"`
	Tier       AttachTier       `json:"tier"`
	Coverage   SemanticCoverage `json:"coverage"`
	Confidence float64          `json:"confidence"`
	KnownGood  bool             `json:"known_good"` // build-id matched a known-good reference entry

	// ReferenceSet records that a non-empty known-good reference set was loaded and
	// could be consulted. Without it, KnownGood=false says only that nothing was
	// available to vouch for the binary, which is not by itself a tamper signal.
	ReferenceSet bool `json:"reference_set,omitempty"`
	// IdentityChanged records that this binary's code section matches one already
	// resolved under a DIFFERENT build-id: the identity changed while the code did
	// not, which is a tamper signal even when no reference set is loaded.
	IdentityChanged bool `json:"identity_changed,omitempty"`

	// Offsets are file offsets into BinaryPath/Library keyed by logical function
	// name: "read","write","handshake" (SSL) or "aead_open","aead_seal" (AEAD),
	// or "go_read","go_write" (Go crypto/tls).
	Offsets map[string]uint64 `json:"offsets"`

	// GoReadRets are file offsets of the RET instructions in Go's
	// crypto/tls.(*Conn).Read, where the inbound uprobe reads the return length
	// (Go's goroutine-stack moves make uretprobe unsafe).
	GoReadRets []uint64 `json:"go_read_rets,omitempty"`
}
