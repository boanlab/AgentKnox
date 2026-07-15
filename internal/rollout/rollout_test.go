// SPDX-License-Identifier: Apache-2.0

package rollout

import (
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

func TestParseMessage(t *testing.T) {
	user := `{"timestamp":"2026-07-15T16:01:52.1Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"capital of France"}]}}`
	asst := `{"timestamp":"2026-07-15T16:01:53.2Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Paris"}]}}`

	if it := ParseLine([]byte(user)); len(it) != 1 || it[0].Kind != types.SemPrompt || it[0].Text != "capital of France" {
		t.Fatalf("user message: %+v", it)
	}
	if it := ParseLine([]byte(asst)); len(it) != 1 || it[0].Kind != types.SemAssistant || it[0].Text != "Paris" {
		t.Fatalf("assistant message: %+v", it)
	}
	if it := ParseLine([]byte(user)); it[0].Time.IsZero() {
		t.Errorf("expected parsed timestamp")
	}
}

func TestParseFunctionCall(t *testing.T) {
	fc := `{"timestamp":"2026-07-15T16:01:54Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\"command\":\"ls -la\"}"}}`
	it := ParseLine([]byte(fc))
	if len(it) != 1 || it[0].Kind != types.SemToolUse {
		t.Fatalf("expected tool_use, got %+v", it)
	}
	if it[0].ToolUse.Name != "shell" || it[0].ToolUse.IntentClass != "exec" || it[0].ToolUse.ID != "call_1" {
		t.Errorf("tool fields: %+v", it[0].ToolUse)
	}
	if cmd, _ := it[0].ToolUse.Input["command"].(string); cmd != "ls -la" {
		t.Errorf("expected parsed command, got %q", cmd)
	}
}

func TestParseFunctionCallOutput(t *testing.T) {
	out := `{"timestamp":"2026-07-15T16:01:55Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"total 0\ndrwxr-xr-x"}}`
	it := ParseLine([]byte(out))
	if len(it) != 1 || it[0].Kind != types.SemToolResult || it[0].ToolResult.ID != "call_1" {
		t.Fatalf("expected tool_result, got %+v", it)
	}
	if it[0].Text != "total 0\ndrwxr-xr-x" {
		t.Errorf("output text: %q", it[0].Text)
	}
}

func TestParseIgnoresNonResponseItems(t *testing.T) {
	for _, l := range []string{
		`{"timestamp":"2026-07-15T16:01:52Z","type":"session_meta","payload":{}}`,
		`{"timestamp":"2026-07-15T16:01:52Z","type":"turn_context","payload":{}}`,
		`not json`,
	} {
		if it := ParseLine([]byte(l)); it != nil {
			t.Errorf("expected nil for %q, got %+v", l, it)
		}
	}
}
