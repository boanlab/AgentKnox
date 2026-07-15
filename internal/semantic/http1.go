// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strconv"
)

// httpBodyDecode frames an inbound HTTP/1.x byte stream into decoded message
// bodies. It de-chunks `Transfer-Encoding: chunked` and gunzips
// `Content-Encoding: gzip` responses (the shape Codex's non-streaming API
// responses use), so the JSON extractor sees plaintext instead of compressed
// bytes.
//
// framed reports whether buf began at an HTTP/1 response boundary and was
// handled here. When false the caller keeps its existing raw byte-stream
// extraction (plaintext JSON and uncompressed SSE flow through unchanged). When
// true, decoded holds the concatenated bodies of every complete response and
// tail is the leftover bytes of an incomplete trailing response to re-buffer.
func httpBodyDecode(buf []byte) (decoded, tail []byte, framed bool) {
	if !bytes.HasPrefix(buf, []byte("HTTP/1.")) {
		return nil, nil, false
	}
	rest := buf
	for bytes.HasPrefix(rest, []byte("HTTP/1.")) {
		hdrEnd := bytes.Index(rest, []byte("\r\n\r\n"))
		if hdrEnd < 0 {
			break // headers incomplete: wait for more
		}
		headers := rest[:hdrEnd]
		bodyStart := hdrEnd + 4

		var body []byte
		var consumed int
		var ok bool
		switch {
		case headerHasToken(headers, "transfer-encoding", "chunked"):
			body, consumed, ok = dechunk(rest[bodyStart:])
		case headerContentLength(headers) >= 0:
			n := headerContentLength(headers)
			if len(rest)-bodyStart < n {
				return decoded, rest, true // body incomplete: wait
			}
			body, consumed, ok = rest[bodyStart:bodyStart+n], n, true
		default:
			// No framing headers (e.g. streaming SSE): cannot delimit the body,
			// hand the rest back as plaintext for line/JSON extraction.
			return append(decoded, rest[bodyStart:]...), nil, true
		}
		if !ok {
			return decoded, rest, true // body incomplete: wait
		}
		// Anthropic/OpenAI responses are compressed with gzip, zlib, or raw
		// deflate depending on the client stack (Bun negotiates deflate; Node
		// negotiates gzip). Decompress whenever a Content-Encoding is present, or
		// when the body is present but does not look like text (a compressed body
		// whose header was truncated before Content-Encoding). Streaming SSE bodies
		// use context-takeover deflate that cannot be inflated from mid-connection;
		// those simply fail to decode here and fall through unchanged.
		if headerHasCompression(headers) || !looksTextual(body) {
			if plain, ok := inflateAny(body); ok {
				body = plain
			}
		}
		decoded = append(decoded, body...)
		rest = rest[bodyStart+consumed:]
	}
	return decoded, rest, true
}

// dechunk decodes an HTTP/1.1 chunked body. It returns the concatenated chunk
// data, the number of input bytes consumed through the terminating zero-length
// chunk, and whether a complete body was present (false = need more bytes).
func dechunk(b []byte) (body []byte, consumed int, complete bool) {
	pos := 0
	for {
		nl := bytes.Index(b[pos:], []byte("\r\n"))
		if nl < 0 {
			return nil, 0, false
		}
		line := b[pos : pos+nl]
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi] // strip chunk extensions
		}
		size, err := strconv.ParseInt(string(bytes.TrimSpace(line)), 16, 64)
		if err != nil || size < 0 {
			return nil, 0, false
		}
		dataStart := pos + nl + 2
		if size == 0 {
			// Terminating chunk; consume the trailing CRLF (skip any trailers).
			end := bytes.Index(b[dataStart:], []byte("\r\n"))
			if end < 0 {
				return nil, 0, false
			}
			return body, dataStart + end + 2, true
		}
		if len(b) < dataStart+int(size)+2 {
			return nil, 0, false // chunk data not fully arrived
		}
		body = append(body, b[dataStart:dataStart+int(size)]...)
		pos = dataStart + int(size) + 2 // skip data + CRLF
		if len(body) > maxBuffer {
			return nil, 0, false
		}
	}
}

// gunzip inflates a gzip stream, bounded to maxBuffer.
func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, maxBuffer))
}

// inflateAny attempts, in order, gzip, zlib (deflate with header), and raw
// deflate decompression of a compressed HTTP body, returning the first that
// yields a non-empty JSON-looking result. Anthropic over Bun uses raw/zlib
// deflate; over Node it uses gzip; OpenAI uses gzip. A whole-body response
// captured from its status line decodes cleanly here; a streaming
// context-takeover SSE body captured mid-connection does not and returns false.
func inflateAny(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	if out, err := gunzip(b); err == nil && looksTextual(out) {
		return out, true
	}
	if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		if out, err := io.ReadAll(io.LimitReader(r, maxBuffer)); err == nil && looksTextual(out) {
			_ = r.Close()
			return out, true
		}
		_ = r.Close()
	}
	fr := flate.NewReader(bytes.NewReader(b))
	if out, err := io.ReadAll(io.LimitReader(fr, maxBuffer)); err == nil && looksTextual(out) {
		_ = fr.Close()
		return out, true
	}
	_ = fr.Close()
	return nil, false
}

// looksTextual reports whether a decoded body plausibly contains JSON/SSE text
// (a majority of printable bytes and at least one JSON structural character).
// Compressed or binary output fails this test, so a wrong decoder is rejected.
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	if printable*10 < len(b)*9 { // < 90% printable
		return false
	}
	return bytes.ContainsAny(b, "{[")
}

// headerHasCompression reports whether the response declares any compressed
// Content-Encoding (gzip, deflate, br, zstd).
func headerHasCompression(headers []byte) bool {
	for _, enc := range []string{"gzip", "deflate", "br", "zstd"} {
		if headerHasToken(headers, "content-encoding", enc) {
			return true
		}
	}
	return false
}

// headerHasToken reports whether the HTTP header block contains a header `name`
// whose value contains `token` (both matched case-insensitively).
func headerHasToken(headers []byte, name, token string) bool {
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if !bytes.EqualFold(bytes.TrimSpace(line[:colon]), []byte(name)) {
			continue
		}
		return bytes.Contains(bytes.ToLower(line[colon+1:]), []byte(token))
	}
	return false
}

// headerContentLength returns the Content-Length value, or -1 if absent/invalid.
func headerContentLength(headers []byte) int {
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if !bytes.EqualFold(bytes.TrimSpace(line[:colon]), []byte("content-length")) {
			continue
		}
		if n, err := strconv.Atoi(string(bytes.TrimSpace(line[colon+1:]))); err == nil {
			return n
		}
	}
	return -1
}
