// SPDX-License-Identifier: Apache-2.0

// Claude Code project-transcript reader. Claude Code's realtime transport is a
// stripped BoringSSL HTTP/2 stream carrying SSE with content compression, which
// the TLS-boundary reassembler cannot reliably decode, so the TLS layer
// contributes round-trip timing while this reader contributes the content
// (prompts, tool calls, results) from the agent's own transcript.
//
// Files live at ~/.claude/projects/<per-cwd project>/<uuid>.jsonl, one JSON
// object per line, append-flushed per turn so they can be tailed live.
package rollout

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/boanlab/agentknox/pkg/types"
)

// ClaudeProjectDirs returns every existing <home>/.claude/projects directory
// across the users an agent might run as. The daemon runs as root, but the
// monitored agent typically runs as an unprivileged user whose transcript lives
// under its own home, so resolving only the daemon's own home would miss it.
func ClaudeProjectDirs() []string {
	return transcriptDirs(filepath.Join(".claude", "projects"))
}

// ClaudeMatch reports whether a filename is a Claude project transcript. The
// per-session files are named <uuid>.jsonl under a per-cwd project directory.
func ClaudeMatch(name string) bool {
	return strings.HasSuffix(name, ".jsonl")
}

// claudeLine is the on-disk envelope for one Claude transcript entry.
type claudeLine struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
}

// claudeMessage is the nested provider message: Content is a plain string for a
// user prompt, or an array of typed blocks for an assistant turn or tool result.
type claudeMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// claudeBlock is one element of a message content array.
type claudeBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Name      string          `json:"name"`
	ID        string          `json:"id"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
}

// ParseClaudeLine parses one Claude project-transcript JSONL line into zero or
// more semantic items. Only user and assistant messages carry conversation
// content; every other line type is ignored.
func ParseClaudeLine(line []byte) []Item {
	var cl claudeLine
	if err := json.Unmarshal(line, &cl); err != nil {
		return nil
	}
	if cl.Type != "user" && cl.Type != "assistant" || len(cl.Message) == 0 {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, cl.Timestamp)

	var m claudeMessage
	if err := json.Unmarshal(cl.Message, &m); err != nil {
		return nil
	}

	// Content as a plain string is a user prompt.
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		return []Item{{Time: ts, Kind: promptKind(m.Role), Text: s}}
	}

	// Content as an array of typed blocks (assistant text/tool_use, tool_result).
	var blocks []claudeBlock
	if json.Unmarshal(m.Content, &blocks) != nil {
		return nil
	}
	var items []Item
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if strings.TrimSpace(b.Text) == "" {
				continue
			}
			items = append(items, Item{Time: ts, Kind: promptKind(m.Role), Text: b.Text})
		case "tool_use":
			var input map[string]any
			_ = json.Unmarshal(b.Input, &input)
			items = append(items, Item{Time: ts, Kind: types.SemToolUse, ToolUse: &types.ToolUse{
				ID:          b.ID,
				Name:        b.Name,
				Input:       input,
				IntentClass: classifyClaudeIntent(b.Name),
			}})
		case "tool_result":
			items = append(items, Item{Time: ts, Kind: types.SemToolResult,
				ToolResult: &types.ToolUse{ID: b.ToolUseID}, Text: claudeResultText(b.Content)})
		}
	}
	return items
}

// promptKind maps a message role to the semantic kind: a user/system/developer
// message is a prompt, everything else is model output.
func promptKind(role string) types.SemanticKind {
	if role == "user" || role == "system" || role == "developer" {
		return types.SemPrompt
	}
	return types.SemAssistant
}

// claudeResultText extracts text from a tool_result content field, which Claude
// serializes as a string or as an array of {type:text,text:...} blocks.
func claudeResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []contentItem
	if json.Unmarshal(raw, &parts) == nil {
		return joinContent(parts)
	}
	return ""
}

// classifyClaudeIntent maps a Claude Code tool name to the coarse read/write/
// exec/network class used for intent-effect mismatch detection.
func classifyClaudeIntent(name string) string {
	switch name {
	case "Bash", "Task":
		return "exec"
	case "Read", "Glob", "Grep", "LS", "NotebookRead":
		return "read"
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return "write"
	case "WebFetch", "WebSearch":
		return "network"
	}
	return ""
}
