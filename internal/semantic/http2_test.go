// SPDX-License-Identifier: Apache-2.0
package semantic

import (
	"testing"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

// h2Frame builds one HTTP/2 DATA frame for stream id sid carrying payload.
func h2DataFrame(sid uint32, payload []byte) []byte {
	n := len(payload)
	hdr := []byte{
		byte(n >> 16), byte(n >> 8), byte(n), // length
		0x0,                                                         // type DATA
		0x0,                                                         // flags
		byte(sid >> 24), byte(sid >> 16), byte(sid >> 8), byte(sid), // stream id
	}
	return append(hdr, payload...)
}

func anthropicSession() *types.AgentSession {
	return &types.AgentSession{Agent: types.AgentClaudeCode, Provider: "anthropic"}
}

// TestHTTP2InterleavedStreams verifies that JSON bodies on two concurrent HTTP/2
// streams are reassembled independently even when their DATA frames interleave
// (the case that corrupts a naive single-buffer JSON scan).
func TestHTTP2InterleavedStreams(t *testing.T) {
	p := New(true, zap.NewNop())
	sess := anthropicSession()

	objA := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"AAA"}}`
	objB := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"BBB"}}`

	// Outbound preface establishes HTTP/2 for this pid.
	p.Feed(types.SemanticChunk{HostPID: 42, Direction: types.DirOutbound, Bytes: append([]byte(h2Preface), h2DataFrame(1, []byte(`{}`))...)}, sess)

	// Inbound: interleave the two objects across streams 3 and 5, split mid-object.
	var wire []byte
	wire = append(wire, h2DataFrame(3, []byte(objA[:20]))...)
	wire = append(wire, h2DataFrame(5, []byte(objB[:20]))...)
	wire = append(wire, h2DataFrame(3, []byte(objA[20:]))...)
	wire = append(wire, h2DataFrame(5, []byte(objB[20:]))...)

	evs := p.Feed(types.SemanticChunk{HostPID: 42, Direction: types.DirInbound, Bytes: wire}, sess)

	var texts []string
	for _, e := range evs {
		if e.Kind == types.SemAssistant {
			texts = append(texts, e.Text)
		}
	}
	if len(texts) != 2 {
		t.Fatalf("want 2 assistant texts, got %d (%v)", len(texts), texts)
	}
	got := map[string]bool{texts[0]: true, texts[1]: true}
	if !got["AAA"] || !got["BBB"] {
		t.Fatalf("interleaved streams corrupted: %v", texts)
	}
}

// TestHTTP2FrameSplitAcrossChunks verifies that a DATA frame split across two TLS
// reads is reassembled.
func TestHTTP2FrameSplitAcrossChunks(t *testing.T) {
	p := New(true, zap.NewNop())
	sess := anthropicSession()
	p.Feed(types.SemanticChunk{HostPID: 9, Direction: types.DirOutbound, Bytes: []byte(h2Preface)}, sess)

	obj := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`
	frame := h2DataFrame(1, []byte(obj))

	// Split the frame mid-header and mid-payload across three chunks.
	if evs := p.Feed(types.SemanticChunk{HostPID: 9, Direction: types.DirInbound, Bytes: frame[:5]}, sess); len(evs) != 0 {
		t.Fatalf("partial frame yielded events: %v", evs)
	}
	if evs := p.Feed(types.SemanticChunk{HostPID: 9, Direction: types.DirInbound, Bytes: frame[5:30]}, sess); len(evs) != 0 {
		t.Fatalf("partial frame yielded events: %v", evs)
	}
	evs := p.Feed(types.SemanticChunk{HostPID: 9, Direction: types.DirInbound, Bytes: frame[30:]}, sess)
	if len(evs) != 1 || evs[0].Text != "hello" {
		t.Fatalf("split frame not reassembled: %+v", evs)
	}
}

// TestHTTP1StillWorks confirms non-HTTP/2 traffic (no preface) uses the byte-scan
// path unchanged.
func TestHTTP1StillWorks(t *testing.T) {
	p := New(true, zap.NewNop())
	sess := anthropicSession()
	body := `POST /v1/messages HTTP/1.1` + "\r\nHost: api\r\n\r\n" +
		`{"model":"claude","messages":[{"role":"user","content":"hi"}]}`
	evs := p.Feed(types.SemanticChunk{HostPID: 1, Direction: types.DirOutbound, Bytes: []byte(body)}, sess)
	found := false
	for _, e := range evs {
		if e.Kind == types.SemPrompt && e.Text == "hi" {
			found = true
		}
	}
	if !found {
		t.Fatalf("HTTP/1 body not parsed: %+v", evs)
	}
}
