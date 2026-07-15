// SPDX-License-Identifier: Apache-2.0

package semantic

// HTTP/2 framing demultiplexer. Agent traffic to LLM providers is almost always
// HTTP/2, which multiplexes concurrent streams onto one connection: DATA frames
// from different streams interleave on the wire. Scanning the raw plaintext for
// balanced JSON objects (the HTTP/1 path) then splices unrelated streams together
// and corrupts the parse. This layer strips 9-byte frame headers and routes each
// DATA frame's payload to a per-stream buffer, so JSON reassembly runs per stream.
//
// HEADERS/SETTINGS/WINDOW_UPDATE and other non-DATA frames are skipped: the JSON
// request/response bodies (and SSE event streams) live in DATA frames.

// h2Preface is the client connection preface that opens every HTTP/2 connection.
var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

const (
	h2FrameHeader = 9
	h2FrameData   = 0x0
	h2FlagPadded  = 0x8
	// h2MaxFrame caps a single frame's declared length; a larger value signals a
	// desync (mid-stream capture, non-h2 bytes) and stops framed decoding.
	h2MaxFrame = 1 << 20
	// h2MaxStreams bounds the per-connection live-stream buffers.
	h2MaxStreams = 256
)

// connState is the reassembly state for one (pid, direction) plaintext stream.
// It is either an HTTP/1 byte buffer or an HTTP/2 frame demultiplexer.
type connState struct {
	mode    int // 0 unknown, 1 http2, -1 http1
	buf     []byte
	raw     []byte            // undecoded HTTP/2 frame bytes
	streams map[uint32][]byte // per-stream reassembled DATA payload (JSON buffer)
	// ws is set once an HTTP/1 connection upgrades to WebSocket (101 Switching
	// Protocols); subsequent bytes are decoded as WebSocket frames (Codex's
	// realtime transport).
	ws *wsConn
}

func newConnState() *connState { return &connState{} }

// streamData is one HTTP/2 stream's newly-appended, reassembled DATA payload.
type streamData struct {
	id  uint32
	buf []byte
}

// pushH2 appends frame bytes and returns the streams that gained DATA payload,
// each with its full current buffer. The caller extracts complete JSON objects
// and writes the remainder back via setStreamRemainder.
func (c *connState) pushH2(data []byte) []streamData {
	if c.streams == nil {
		c.streams = make(map[uint32][]byte)
	}
	c.raw = append(c.raw, data...)
	touched := map[uint32]bool{}
	for len(c.raw) >= h2FrameHeader {
		length := int(c.raw[0])<<16 | int(c.raw[1])<<8 | int(c.raw[2])
		if length > h2MaxFrame {
			c.raw = nil // desync: drop and resynchronize on the next connection
			break
		}
		if h2FrameHeader+length > len(c.raw) {
			break // incomplete frame; wait for more bytes
		}
		ftype := c.raw[3]
		flags := c.raw[4]
		sid := (uint32(c.raw[5])<<24 | uint32(c.raw[6])<<16 | uint32(c.raw[7])<<8 | uint32(c.raw[8])) & 0x7fffffff
		payload := c.raw[h2FrameHeader : h2FrameHeader+length]

		if ftype == h2FrameData && sid != 0 {
			d := payload
			if flags&h2FlagPadded != 0 && len(d) > 0 {
				padLen := int(d[0])
				if 1+padLen <= len(d) {
					d = d[1 : len(d)-padLen]
				} else {
					d = nil
				}
			}
			if _, ok := c.streams[sid]; !ok && len(c.streams) >= h2MaxStreams {
				c.evictStream()
			}
			c.streams[sid] = append(c.streams[sid], d...)
			if len(c.streams[sid]) > maxBuffer {
				c.streams[sid] = c.streams[sid][len(c.streams[sid])-maxBuffer:]
			}
			touched[sid] = true
		}
		c.raw = c.raw[h2FrameHeader+length:]
	}

	out := make([]streamData, 0, len(touched))
	for sid := range touched {
		out = append(out, streamData{id: sid, buf: c.streams[sid]})
	}
	return out
}

// setStreamRemainder stores the trailing incomplete bytes for a stream, dropping
// the stream when nothing remains.
func (c *connState) setStreamRemainder(sid uint32, rem []byte) {
	if len(rem) == 0 {
		delete(c.streams, sid)
		return
	}
	c.streams[sid] = append([]byte(nil), rem...)
}

// evictStream drops an arbitrary stream buffer to bound memory when a connection
// accumulates too many concurrently-open streams.
func (c *connState) evictStream() {
	for sid := range c.streams {
		delete(c.streams, sid)
		return
	}
}

// looksLikeH2Preface reports whether b begins with the HTTP/2 client preface.
func looksLikeH2Preface(b []byte) bool {
	if len(b) < len(h2Preface) {
		return false
	}
	for i := range h2Preface {
		if b[i] != h2Preface[i] {
			return false
		}
	}
	return true
}
