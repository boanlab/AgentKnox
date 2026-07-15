// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"testing"
)

// wsFrameBytes builds one WebSocket frame. If key is non-nil the payload is
// masked with it (client→server). rsv1 marks a permessage-deflate payload.
func wsFrameBytes(opcode byte, fin, rsv1 bool, key []byte, payload []byte) []byte {
	var b bytes.Buffer
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	b.WriteByte(b0)
	b1 := byte(0)
	if key != nil {
		b1 = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		b.WriteByte(b1 | byte(n))
	case n < 65536:
		b.WriteByte(b1 | 126)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(n))
		b.Write(l[:])
	default:
		b.WriteByte(b1 | 127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		b.Write(l[:])
	}
	p := append([]byte(nil), payload...)
	if key != nil {
		b.Write(key)
		for i := range p {
			p[i] ^= key[i&3]
		}
	}
	b.Write(p)
	return b.Bytes()
}

// wsDeflate compresses with raw DEFLATE and strips the trailing sync-flush marker
// (the permessage-deflate sender's job).
func wsDeflate(data []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.DefaultCompression)
	_, _ = w.Write(data)
	_ = w.Flush()
	out := b.Bytes()
	if bytes.HasSuffix(out, []byte{0x00, 0x00, 0xff, 0xff}) {
		out = out[:len(out)-4]
	}
	return out
}

// TestWSMaskedPlain covers an unmasked server frame and a masked client frame,
// both uncompressed; the framing must be stripped and payloads recovered.
func TestWSMaskedPlain(t *testing.T) {
	var w wsConn
	server := wsFrameBytes(0x1, true, false, nil, []byte(`{"type":"response","text":"hello"}`))
	client := wsFrameBytes(0x1, true, false, []byte{0xa1, 0xb2, 0xc3, 0xd4}, []byte(`{"type":"request"}`))
	msgs := w.pushWS(append(server, client...))
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if string(msgs[0]) != `{"type":"response","text":"hello"}` {
		t.Errorf("server msg wrong: %q", msgs[0])
	}
	if string(msgs[1]) != `{"type":"request"}` {
		t.Errorf("client msg (unmask) wrong: %q", msgs[1])
	}
}

// TestWSDeflate covers a permessage-deflate (RSV1) compressed message, fed in two
// TLS fragments to exercise cross-chunk frame reassembly.
func TestWSDeflate(t *testing.T) {
	var w wsConn
	body := []byte(`{"type":"response.output_text.delta","delta":"The capital of France is Paris."}`)
	frame := wsFrameBytes(0x2, true, true, nil, wsDeflate(body))
	cut := len(frame) / 2
	var msgs [][]byte
	msgs = append(msgs, w.pushWS(frame[:cut])...)
	msgs = append(msgs, w.pushWS(frame[cut:])...)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if string(msgs[0]) != string(body) {
		t.Errorf("inflated msg wrong:\n got %q\nwant %q", msgs[0], body)
	}
}

// TestWSFragmented covers a message split across a text frame (FIN=0) and a
// continuation frame (opcode 0, FIN=1).
func TestWSFragmented(t *testing.T) {
	var w wsConn
	f1 := wsFrameBytes(0x1, false, false, nil, []byte(`{"a":`))
	f2 := wsFrameBytes(0x0, true, false, nil, []byte(`1}`))
	msgs := w.pushWS(append(f1, f2...))
	if len(msgs) != 1 || string(msgs[0]) != `{"a":1}` {
		t.Fatalf("expected reassembled {\"a\":1}, got %v", msgs)
	}
}
