// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"

	"github.com/boanlab/agentknox/pkg/types"
)

// wsConn decodes a WebSocket byte stream (RFC 6455) into application messages.
// Codex's realtime transport upgrades to WebSocket (HTTP/1.1 101 Switching
// Protocols), so the conversation JSON arrives as WebSocket frames: masked
// (client to server) and, when permessage-deflate (RFC 7692) is negotiated,
// DEFLATE-compressed, which the plain HTTP/JSON reassembler cannot read. This
// decoder strips the framing, unmasks, reassembles fragments, and inflates, so
// the JSON extractor sees plaintext.
type wsConn struct {
	buf     []byte // undecoded frame bytes
	msg     []byte // reassembled payload of the in-progress (fragmented) message
	msgRSV1 bool   // first frame of the current message had RSV1 (compressed)
	inflate wsInflater
}

// pushWS appends raw bytes and returns any complete application messages
// (decompressed), ready for JSON extraction.
func (w *wsConn) pushWS(data []byte) [][]byte {
	w.buf = append(w.buf, data...)
	var out [][]byte
	for {
		payload, rsv1, fin, opcode, n, ok := wsFrame(w.buf)
		if !ok {
			break // incomplete frame; wait for more
		}
		w.buf = w.buf[n:]
		// Control frames (close/ping/pong, opcode >= 0x8) carry no app data.
		if opcode >= 0x8 {
			continue
		}
		if len(w.msg) == 0 && opcode != 0 {
			w.msgRSV1 = rsv1 // opcode != 0 starts a message; RSV1 set on the first frame
		}
		w.msg = append(w.msg, payload...)
		if !fin {
			continue // more fragments to come
		}
		msg := w.msg
		w.msg = nil
		if w.msgRSV1 {
			if plain, err := w.inflate.inflate(msg); err == nil {
				msg = plain
			} else {
				continue // undecodable; drop this message
			}
		}
		if len(msg) > 0 {
			out = append(out, msg)
		}
	}
	return out
}

// wsFrame parses one WebSocket frame from buf. It returns the (unmasked) payload,
// the RSV1 bit, the FIN bit, the opcode, the number of bytes consumed, and
// whether a complete frame was present.
func wsFrame(buf []byte) (payload []byte, rsv1, fin bool, opcode byte, consumed int, ok bool) {
	if len(buf) < 2 {
		return nil, false, false, 0, 0, false
	}
	b0, b1 := buf[0], buf[1]
	fin = b0&0x80 != 0
	rsv1 = b0&0x40 != 0
	opcode = b0 & 0x0f
	masked := b1&0x80 != 0
	length := uint64(b1 & 0x7f)
	pos := 2
	switch length {
	case 126:
		if len(buf) < pos+2 {
			return nil, false, false, 0, 0, false
		}
		length = uint64(binary.BigEndian.Uint16(buf[pos : pos+2]))
		pos += 2
	case 127:
		if len(buf) < pos+8 {
			return nil, false, false, 0, 0, false
		}
		length = binary.BigEndian.Uint64(buf[pos : pos+8])
		pos += 8
	}
	var maskKey []byte
	if masked {
		if len(buf) < pos+4 {
			return nil, false, false, 0, 0, false
		}
		maskKey = buf[pos : pos+4]
		pos += 4
	}
	if length > maxBuffer || len(buf) < pos+int(length) {
		return nil, false, false, 0, 0, false
	}
	payload = append([]byte(nil), buf[pos:pos+int(length)]...)
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i&3]
		}
	}
	return payload, rsv1, fin, opcode, pos + int(length), true
}

// wsInflater inflates permessage-deflate message bodies. Per RFC 7692 the sender
// strips the trailing empty block, so the receiver appends the 0x00 0x00 0xff
// 0xff sync-flush marker before inflating. Context takeover is honored by
// carrying the last 32 KiB of decompressed output forward as the LZ77 dictionary.
type wsInflater struct {
	dict []byte
}

func (w *wsInflater) inflate(compressed []byte) ([]byte, error) {
	data := append(append([]byte(nil), compressed...), 0x00, 0x00, 0xff, 0xff)
	fr := flate.NewReaderDict(bytes.NewReader(data), w.dict)
	out, err := io.ReadAll(io.LimitReader(fr, maxBuffer))
	_ = fr.Close()
	// The sync-flush marker is a non-final block, so flate reports an unexpected
	// EOF at the end of the message; that is normal, not a failure.
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	combined := append(w.dict, out...)
	if len(combined) > 32768 {
		combined = combined[len(combined)-32768:]
	}
	w.dict = combined
	return out, nil
}

// wsUpgradeSeen reports a WebSocket handshake at the start of buf: an inbound
// 101 Switching Protocols response, or an outbound `Upgrade: websocket` request.
func wsUpgradeSeen(buf []byte, dir types.Direction) bool {
	if dir == types.DirInbound {
		return bytes.HasPrefix(buf, []byte("HTTP/1.1 101")) || bytes.HasPrefix(buf, []byte("HTTP/1.0 101"))
	}
	// Outbound: an HTTP request whose header block asks to upgrade to websocket.
	if hdrEnd := bytes.Index(buf, []byte("\r\n\r\n")); hdrEnd >= 0 {
		return headerHasToken(buf[:hdrEnd], "upgrade", "websocket")
	}
	return false
}

// bytesIndexCRLFCRLF returns the offset just past the end of an HTTP header
// block (the first "\r\n\r\n"), or -1 if it has not fully arrived.
func bytesIndexCRLFCRLF(buf []byte) int {
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	return -1
}

// wsBatch extracts JSON objects from decoded WebSocket messages into a single
// stream-0 batch (nil when nothing parses).
func wsBatch(msgs [][]byte) []objBatch {
	var objs [][]byte
	for _, m := range msgs {
		o, _ := extractObjects(m)
		objs = append(objs, o...)
	}
	if len(objs) == 0 {
		return nil
	}
	return []objBatch{{stream: 0, objs: objs}}
}
