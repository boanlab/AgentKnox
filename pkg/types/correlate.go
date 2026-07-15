// SPDX-License-Identifier: Apache-2.0
package types

import "time"

// EdgeKind labels a typed edge in the provenance/session graph.
type EdgeKind string

const (
	EdgeFork      EdgeKind = "fork"
	EdgeExec      EdgeKind = "exec"
	EdgeFileTouch EdgeKind = "file_touch"
	EdgeConnect   EdgeKind = "connect"
	EdgeDNS       EdgeKind = "dns"
	EdgeToolUse   EdgeKind = "tool_use"
	EdgeDBQuery   EdgeKind = "db_query"
)

// GraphEdge is one edge in the causal session graph.
type GraphEdge struct {
	SessionID string    `json:"session_id"`
	Kind      EdgeKind  `json:"kind"`
	Time      time.Time `json:"time"`
	SrcPID    int32     `json:"src_pid"`
	Resource  string    `json:"resource,omitempty"`
	RefEvent  string    `json:"ref_event,omitempty"` // originating EventID
}

// Effect is the reachable system effect attributed to a tool_use intent.
type Effect struct {
	Category  Category `json:"category"`
	Operation string   `json:"operation"`
	Resource  string   `json:"resource"`
	EventID   string   `json:"event_id"`
}

// CorrelatedAction links a semantic intent (tool_use) to the system effects it
// caused, with taint and intent-effect mismatch analysis. Produced by the correlation engine.
type CorrelatedAction struct {
	ActionID  string    `json:"action_id"` // UUIDv7
	SessionID string    `json:"session_id"`
	HostPID   int32     `json:"host_pid,omitempty"` // pid that produced the effect
	Time      time.Time `json:"time"`

	ToolUseID   string   `json:"tool_use_id,omitempty"`
	ToolName    string   `json:"tool_name,omitempty"`
	IntentClass string   `json:"intent_class,omitempty"` // read|write|network|exec
	Effects     []Effect `json:"effects"`

	Taint          []string `json:"taint,omitempty"`
	Mismatch       bool     `json:"mismatch,omitempty"`
	MismatchReason string   `json:"mismatch_reason,omitempty"`
	Confidence     float64  `json:"confidence"`
}
