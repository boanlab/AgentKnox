// SPDX-License-Identifier: Apache-2.0

// Gemini CLI chat-transcript reader. Gemini CLI records each session as an
// append-only JSONL chat log under ~/.gemini/tmp/<project>/chats/<uuid>/<uuid>.jsonl,
// one JSON object per line. The TLS boundary contributes round-trip timing while
// this reader contributes the content (prompts, tool calls, results).
package rollout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/boanlab/agentknox/pkg/types"
)

// GeminiTranscriptDirs returns every existing ~/.gemini/tmp directory across the
// users an agent might run as (see ClaudeProjectDirs for the rationale).
func GeminiTranscriptDirs() []string {
	return transcriptDirs(filepath.Join(".gemini", "tmp"))
}

// transcriptDirs resolves rel under /root and every /home/* user, returning the
// directories that exist. Shared by the Claude and Gemini readers.
func transcriptDirs(rel string) []string {
	homes := []string{"/root"}
	if h, err := os.UserHomeDir(); err == nil {
		homes = append(homes, h)
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	seen := make(map[string]bool)
	var dirs []string
	for _, h := range homes {
		d := filepath.Join(h, rel)
		if seen[d] {
			continue
		}
		seen[d] = true
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// GeminiMatch reports whether a filename is a Gemini chat transcript. Session
// index files (session-*.jsonl) carry only metadata and parse to nothing, so a
// plain .jsonl match is sufficient.
func GeminiMatch(name string) bool {
	return strings.HasSuffix(name, ".jsonl")
}

// geminiLine is one Gemini chat-log entry. A message line carries a type; a $set
// mutation line and the session-header line do not and are ignored.
type geminiLine struct {
	Type      string           `json:"type"`
	Timestamp string           `json:"timestamp"`
	Content   json.RawMessage  `json:"content"`
	ToolCalls []geminiToolCall `json:"toolCalls"`
}

type geminiToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// geminiBlock is one element of a user-message content array: free text, or the
// functionResponse envelope Gemini uses for tool results.
type geminiBlock struct {
	Text             string          `json:"text"`
	FunctionResponse *geminiFuncResp `json:"functionResponse"`
}

type geminiFuncResp struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

// ParseGeminiLine parses one Gemini chat-log JSONL line into zero or more
// semantic items. Only typed user and assistant ("gemini") messages carry
// conversation content.
func ParseGeminiLine(line []byte) []Item {
	var gl geminiLine
	if err := json.Unmarshal(line, &gl); err != nil || gl.Type == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, gl.Timestamp)

	switch gl.Type {
	case "user":
		return parseGeminiUser(gl.Content, ts)
	case "gemini", "model", "assistant":
		return parseGeminiAssistant(gl.Content, gl.ToolCalls, ts)
	}
	return nil
}

// parseGeminiUser handles a user message: an array of {text} blocks (a prompt),
// or {functionResponse} blocks (tool results returned to the model).
func parseGeminiUser(raw json.RawMessage, ts time.Time) []Item {
	var blocks []geminiBlock
	if json.Unmarshal(raw, &blocks) != nil {
		var s string
		if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
			return []Item{{Time: ts, Kind: types.SemPrompt, Text: s}}
		}
		return nil
	}
	var text string
	var items []Item
	for _, b := range blocks {
		switch {
		case b.Text != "":
			if text != "" {
				text += "\n"
			}
			text += b.Text
		case b.FunctionResponse != nil:
			items = append(items, Item{Time: ts, Kind: types.SemToolResult,
				ToolResult: &types.ToolUse{ID: b.FunctionResponse.ID},
				Text:       string(b.FunctionResponse.Response)})
		}
	}
	if strings.TrimSpace(text) != "" {
		items = append([]Item{{Time: ts, Kind: types.SemPrompt, Text: text}}, items...)
	}
	return items
}

// parseGeminiAssistant handles a "gemini" message: a text string plus any
// toolCalls the model issued on that turn.
func parseGeminiAssistant(raw json.RawMessage, calls []geminiToolCall, ts time.Time) []Item {
	var items []Item
	var s string
	if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
		items = append(items, Item{Time: ts, Kind: types.SemAssistant, Text: s})
	}
	for _, tc := range calls {
		var input map[string]any
		_ = json.Unmarshal(tc.Args, &input)
		items = append(items, Item{Time: ts, Kind: types.SemToolUse, ToolUse: &types.ToolUse{
			ID:          tc.ID,
			Name:        tc.Name,
			Input:       input,
			IntentClass: classifyGeminiIntent(tc.Name),
		}})
	}
	return items
}

// classifyGeminiIntent maps a Gemini CLI tool name to a coarse intent class.
func classifyGeminiIntent(name string) string {
	switch name {
	case "run_shell_command":
		return "exec"
	case "read_file", "read_many_files", "list_directory", "glob", "search_file_content":
		return "read"
	case "write_file", "replace":
		return "write"
	case "web_fetch", "google_web_search":
		return "network"
	}
	return ""
}
