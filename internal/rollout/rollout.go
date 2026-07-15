// SPDX-License-Identifier: Apache-2.0

// Package rollout reads agent session transcripts as a semantic-content source,
// one reader per vendor: OpenAI Codex CLI here, Claude Code, Gemini CLI, GitHub
// Copilot CLI, and Crush in the other files of this package.
//
// Codex's realtime transport is a permessage-deflate WebSocket that the
// TLS-boundary reassembler cannot reliably decode, so the TLS layer contributes
// round-trip timing while this reader contributes the content (prompts, tool
// calls, results) from the agent's own transcript. Files live at
// $CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl, one JSON object per
// line, append-flushed per turn so they can be tailed live.
package rollout

import (
	"encoding/json"
	"time"

	"github.com/boanlab/agentknox/pkg/types"
)

// Item is one parsed transcript entry, provider-neutral. The daemon stamps
// session/identity fields and emits it as a types.SemanticEvent.
type Item struct {
	Time       time.Time
	Kind       types.SemanticKind
	Text       string
	ToolUse    *types.ToolUse // set for SemToolUse
	ToolResult *types.ToolUse // set for SemToolResult
}

// rolloutLine is the on-disk envelope: {timestamp, type, payload}.
type rolloutLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// ParseLine parses one rollout JSONL line into zero or more semantic items. Only
// response_item lines carry conversation content; other line types (session_meta,
// turn_context, event_msg, world_state) are ignored.
func ParseLine(line []byte) []Item {
	var rl rolloutLine
	if err := json.Unmarshal(line, &rl); err != nil || rl.Type != "response_item" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, rl.Timestamp)

	var p struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		Content []contentItem   `json:"content"`
		Name    string          `json:"name"`
		CallID  string          `json:"call_id"`
		Args    json.RawMessage `json:"arguments"`
		Output  json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(rl.Payload, &p); err != nil {
		return nil
	}

	switch p.Type {
	case "message", "agent_message":
		text := joinContent(p.Content)
		if text == "" {
			return nil
		}
		kind := types.SemAssistant
		if p.Role == "user" || p.Role == "developer" || p.Role == "system" {
			kind = types.SemPrompt
		}
		return []Item{{Time: ts, Kind: kind, Text: text}}

	case "function_call", "custom_tool_call", "local_shell_call":
		input := decodeArgs(p.Args)
		return []Item{{Time: ts, Kind: types.SemToolUse, ToolUse: &types.ToolUse{
			ID:          p.CallID,
			Name:        p.Name,
			Input:       input,
			IntentClass: classifyIntent(p.Name),
		}}}

	case "function_call_output", "custom_tool_call_output":
		return []Item{{Time: ts, Kind: types.SemToolResult,
			ToolResult: &types.ToolUse{ID: p.CallID}, Text: outputText(p.Output)}}
	}
	return nil
}

// contentItem is one part of a message's content array.
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func joinContent(parts []contentItem) string {
	var s string
	for _, c := range parts {
		if c.Text == "" {
			continue
		}
		if s != "" {
			s += "\n"
		}
		s += c.Text
	}
	return s
}

// decodeArgs decodes a function-call arguments value, which Codex serializes as a
// JSON string (function_call) or an object (custom_tool_call).
func decodeArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	// Try object first, then a JSON-encoded string.
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		return obj
	}
	var str string
	if json.Unmarshal(raw, &str) == nil && str != "" {
		_ = json.Unmarshal([]byte(str), &obj)
		return obj
	}
	return nil
}

// outputText extracts text from a function_call_output payload, which is either a
// string or an object with a `content` string.
func outputText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str
	}
	var obj struct {
		Content string `json:"content"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Content
	}
	return ""
}

// classifyIntent derives a coarse read/write/exec/network class from a Codex tool
// name (mirrors the semantic parser's classifier for the tool names Codex uses).
func classifyIntent(name string) string {
	switch name {
	case "shell", "local_shell", "run", "exec", "bash":
		return "exec"
	case "read_file", "read", "cat", "list_dir", "grep", "search":
		return "read"
	case "write_file", "apply_patch", "edit", "create_file":
		return "write"
	case "web_search", "fetch", "browser":
		return "network"
	}
	return ""
}
