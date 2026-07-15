// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

// gzipChunkedResponse builds an HTTP/1.1 response with a gzip-compressed,
// chunked-transfer-encoded body: the shape of Codex's non-streaming API responses.
func gzipChunkedResponse(body string) []byte {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(body))
	_ = w.Close()
	comp := gz.Bytes()

	var out bytes.Buffer
	out.WriteString("HTTP/1.1 200 OK\r\n")
	out.WriteString("Content-Type: application/json\r\n")
	out.WriteString("Transfer-Encoding: chunked\r\n")
	out.WriteString("Content-Encoding: gzip\r\n\r\n")
	// Emit the gzip stream as two chunks to exercise de-chunking.
	half := len(comp) / 2
	fmt.Fprintf(&out, "%x\r\n", half)
	out.Write(comp[:half])
	out.WriteString("\r\n")
	fmt.Fprintf(&out, "%x\r\n", len(comp)-half)
	out.Write(comp[half:])
	out.WriteString("\r\n0\r\n\r\n")
	return out.Bytes()
}

// TestCodexGzipChunkedResponse proves an inbound gzip+chunked Anthropic response
// (Codex talking to the Anthropic API) is de-chunked, gunzipped and parsed into
// an assistant event.
func TestCodexGzipChunkedResponse(t *testing.T) {
	body := `{"model":"claude-sonnet-5","id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"Paris"}]}`
	resp := gzipChunkedResponse(body)

	p := New(true, nil)
	sess := &types.AgentSession{ID: "cdx", Agent: types.AgentCodex}
	// Feed in two fragments to exercise cross-chunk reassembly.
	cut := len(resp) / 3
	var evs []types.SemanticEvent
	evs = append(evs, p.Feed(types.SemanticChunk{HostPID: 1, ConnID: 7, Direction: types.DirInbound, Bytes: resp[:cut]}, sess)...)
	evs = append(evs, p.Feed(types.SemanticChunk{HostPID: 1, ConnID: 7, Direction: types.DirInbound, Bytes: resp[cut:]}, sess)...)

	ev, ok := firstOfKind(evs, types.SemAssistant)
	if !ok {
		t.Fatalf("expected SemAssistant from gzip+chunked response, got %+v", kinds(evs))
	}
	if ev.Text != "Paris" {
		t.Errorf("expected assistant text %q, got %q", "Paris", ev.Text)
	}
}

// TestHTTP1PlainResponsePassthrough ensures a plain (uncompressed) HTTP/1
// response body still parses, so the decoder does not regress the SSE path.
func TestHTTP1PlainResponsePassthrough(t *testing.T) {
	body := `{"type":"message_start","message":{"model":"claude-sonnet-5"}}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: " + body + "\n\n"
	p := New(true, nil)
	sess := &types.AgentSession{ID: "cdx", Agent: types.AgentCodex}
	evs := p.Feed(types.SemanticChunk{HostPID: 2, ConnID: 9, Direction: types.DirInbound, Bytes: []byte(resp)}, sess)
	// message_start carries usage only; assert it did not error and produced no garbage.
	for _, e := range evs {
		if e.Kind == "" {
			t.Errorf("unexpected empty-kind event: %+v", e)
		}
	}
}
