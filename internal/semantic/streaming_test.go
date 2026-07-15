// SPDX-License-Identifier: Apache-2.0
package semantic

import (
	"testing"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

func feedDispatch(p *Parser, fc *feedCtx, objs ...string) []types.SemanticEvent {
	var out []types.SemanticEvent
	for _, o := range objs {
		out = append(out, p.dispatch([]byte(o), fc)...)
	}
	return out
}

// TestStreamingToolUseReassembly verifies that a tool_use whose input is streamed
// as input_json_delta fragments is reassembled into the full tool input at
// content_block_stop.
func TestStreamingToolUseReassembly(t *testing.T) {
	p := New(true, zap.NewNop())
	fc := &feedCtx{pid: 7, sess: &types.AgentSession{Agent: types.AgentClaudeCode, Provider: "anthropic"}}
	evs := feedDispatch(p, fc,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"Bash"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm "}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"-rf /\"}"}}`,
		`{"type":"content_block_stop","index":0}`,
	)
	if len(evs) != 1 {
		t.Fatalf("expected 1 tool_use event, got %d", len(evs))
	}
	tu := evs[0]
	if tu.Kind != types.SemToolUse || tu.ToolUse == nil {
		t.Fatalf("wrong event kind %s", tu.Kind)
	}
	if tu.ToolUse.Name != "Bash" || tu.ToolUse.Input["command"] != "rm -rf /" {
		t.Errorf("bad reassembly: %+v", tu.ToolUse)
	}
	if tu.ToolUse.IntentClass != "exec" {
		t.Errorf("intent = %q, want exec", tu.ToolUse.IntentClass)
	}
}

// TestStreamingUsage verifies token accounting from a message_delta usage block.
func TestStreamingUsage(t *testing.T) {
	p := New(true, zap.NewNop())
	fc := &feedCtx{pid: 7, sess: &types.AgentSession{Agent: types.AgentClaudeCode, Provider: "anthropic"}}
	evs := feedDispatch(p, fc, `{"type":"message_delta","usage":{"output_tokens":42}}`)
	if len(evs) != 1 || evs[0].Kind != types.SemUsage || evs[0].TokensOut != 42 {
		t.Errorf("usage event: %+v", evs)
	}
}
