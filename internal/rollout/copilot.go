// SPDX-License-Identifier: Apache-2.0

// GitHub Copilot CLI session-transcript reader. Copilot CLI ships as a
// compiled Node "single executable application" that performs its
// TLS, HTTP/2 (undici) and SSE parsing entirely in JavaScript/WASM inside V8,
// so no native uprobe boundary (SSL_read, decompression, or nghttp2) ever holds
// the model plaintext. This reader is therefore Copilot's sole semantic-content
// source, tailing the agent's own append-only event log; the TLS layer
// contributes nothing (coverage none) while the syscall/LSM layer enforces
// unconditionally.
//
// Files live at ~/.copilot/session-state/<session-uuid>/events.jsonl, one JSON
// object per line, appended per event so they can be tailed live.
package rollout

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/boanlab/agentknox/pkg/types"
)

// CopilotSessionDirs returns every existing ~/.copilot/session-state directory
// across the users an agent might run as (see ClaudeProjectDirs for the
// rationale on resolving other users' homes).
func CopilotSessionDirs() []string {
	return transcriptDirs(filepath.Join(".copilot", "session-state"))
}

// CopilotMatch reports whether a filename is a Copilot session event log. Each
// session's events live in <session-uuid>/events.jsonl under session-state.
func CopilotMatch(name string) bool {
	return name == "events.jsonl"
}

// copilotEvent is the on-disk envelope for one Copilot event: a type tag, a
// nested data object, and a timestamp.
type copilotEvent struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

// ParseCopilotLine parses one Copilot events.jsonl line into zero or more
// semantic items. Only user/assistant messages and tool-execution events carry
// conversation content; every other event type is ignored.
func ParseCopilotLine(line []byte) []Item {
	var ev copilotEvent
	if err := json.Unmarshal(line, &ev); err != nil || ev.Type == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, ev.Timestamp)

	switch ev.Type {
	case "user.message":
		var d struct {
			Content string `json:"content"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		if strings.TrimSpace(d.Content) == "" {
			return nil
		}
		return []Item{{Time: ts, Kind: types.SemPrompt, Text: d.Content}}

	case "assistant.message":
		var d struct {
			Content string `json:"content"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		if strings.TrimSpace(d.Content) == "" {
			return nil
		}
		return []Item{{Time: ts, Kind: types.SemAssistant, Text: d.Content}}

	case "tool.execution_start":
		var d struct {
			ToolCallID string          `json:"toolCallId"`
			ToolName   string          `json:"toolName"`
			Arguments  json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		var input map[string]any
		_ = json.Unmarshal(d.Arguments, &input)
		return []Item{{Time: ts, Kind: types.SemToolUse, ToolUse: &types.ToolUse{
			ID:          d.ToolCallID,
			Name:        d.ToolName,
			Input:       input,
			IntentClass: classifyCopilotIntent(d.ToolName),
		}}}

	case "tool.execution_complete":
		var d struct {
			ToolCallID string `json:"toolCallId"`
			Result     struct {
				Content string `json:"content"`
			} `json:"result"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		return []Item{{Time: ts, Kind: types.SemToolResult,
			ToolResult: &types.ToolUse{ID: d.ToolCallID}, Text: d.Result.Content}}
	}
	return nil
}

// classifyCopilotIntent maps a Copilot CLI tool name to the coarse read/write/
// exec/network class used for intent-effect mismatch detection.
func classifyCopilotIntent(name string) string {
	switch name {
	case "bash", "shell":
		return "exec"
	case "view", "read", "grep", "glob", "ls", "search":
		return "read"
	case "edit", "write", "create", "str_replace", "str_replace_editor", "apply_patch":
		return "write"
	case "fetch", "web_search", "browser":
		return "network"
	}
	return ""
}
