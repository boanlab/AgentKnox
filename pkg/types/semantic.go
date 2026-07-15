// SPDX-License-Identifier: Apache-2.0
package types

import "time"

// Direction of a captured TLS/plaintext chunk relative to the agent process.
type Direction string

const (
	DirOutbound Direction = "out" // agent → server (prompt, tool_result, DB query)
	DirInbound  Direction = "in"  // server → agent (assistant response, tool schema)
)

// SemanticChunk is a raw plaintext fragment lifted from a TLS boundary by the
// Semantic Sensor before HTTP/2 / SSE reassembly.
type SemanticChunk struct {
	TimestampNS uint64    `json:"timestamp_ns"`
	HostTID     int32     `json:"host_tid"`
	HostPID     int32     `json:"host_pid"`
	CgroupID    uint64    `json:"cgroup_id"`
	Direction   Direction `json:"direction"`
	ConnID      uint64    `json:"-"` // TLS connection object ptr; demuxes concurrent connections
	Bytes       []byte    `json:"-"`
}

// SemanticKind classifies a parsed semantic event.
type SemanticKind string

const (
	SemPrompt     SemanticKind = "prompt"      // user/system message to model
	SemAssistant  SemanticKind = "assistant"   // model text response
	SemToolUse    SemanticKind = "tool_use"    // model-requested tool call
	SemToolResult SemanticKind = "tool_result" // tool output returned to model
	SemMCP        SemanticKind = "mcp"         // MCP JSON-RPC message
	SemDBQuery    SemanticKind = "db_query"    // DB wire query
	SemUsage      SemanticKind = "usage"       // token/usage accounting
)

// ToolUse describes a model-requested tool invocation (intent).
type ToolUse struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Input map[string]any `json:"input,omitempty"`
	// IntentClass is a coarse read/write/network/exec classification derived
	// from the tool name+input, used for intent-effect mismatch detection.
	IntentClass string `json:"intent_class,omitempty"`
}

// DBQuery is a parsed database wire-protocol operation.
type DBQuery struct {
	Engine     string `json:"engine"`   // postgres|mysql|mongodb
	Endpoint   string `json:"endpoint"` // host:port
	Database   string `json:"database,omitempty"`
	Table      string `json:"table,omitempty"` // or collection
	Op         string `json:"op,omitempty"`    // select|insert|update|delete|find|...
	StmtRedact string `json:"stmt_redacted,omitempty"`
	HasWhere   bool   `json:"has_where,omitempty"`
}

// SemanticEvent is the unified semantic-layer event after provider/MCP/DB parsing.
type SemanticEvent struct {
	EventID     string    `json:"event_id"` // UUIDv7
	TimestampNS uint64    `json:"timestamp_ns"`
	Time        time.Time `json:"time"`
	SessionID   string    `json:"session_id"`
	Agent       AgentKind `json:"agent"`
	HostPID     int32     `json:"host_pid"`
	CgroupID    uint64    `json:"cgroup_id"`

	Kind     SemanticKind `json:"kind"`
	Provider string       `json:"provider,omitempty"` // anthropic|openai|...
	Model    string       `json:"model,omitempty"`

	// Populated by kind:
	Text       string         `json:"text,omitempty"`        // prompt/assistant (redacted per policy)
	ToolUse    *ToolUse       `json:"tool_use,omitempty"`    // SemToolUse
	ToolResult *ToolUse       `json:"tool_result,omitempty"` // SemToolResult (ID links to ToolUse)
	MCPMethod  string         `json:"mcp_method,omitempty"`  // SemMCP
	MCPParams  map[string]any `json:"mcp_params,omitempty"`
	DBQuery    *DBQuery       `json:"db_query,omitempty"` // SemDBQuery

	// Bookkeeping
	Redacted  bool `json:"redacted"`
	TokensIn  int  `json:"tokens_in,omitempty"`
	TokensOut int  `json:"tokens_out,omitempty"`
}
