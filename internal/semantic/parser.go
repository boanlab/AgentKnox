// SPDX-License-Identifier: Apache-2.0

// Package semantic implements the Semantic Parser. It
// reassembles raw plaintext TLS chunks lifted from the encryption boundary by
// the Semantic Sensor into provider (Anthropic/OpenAI), MCP (JSON-RPC) and DB
// (wire-protocol) semantic events.
//
// The reassembly strategy is deliberately tolerant: TLS chunks arrive as
// fragments that do not respect HTTP/2 frame or SSE line boundaries, so instead
// of a full HTTP parser the buffer is scanned for balanced top-level JSON
// objects. Each complete object is dispatched to a format parser; the trailing
// incomplete remainder is kept buffered for the next chunk. This handles the
// two shapes that occur in practice: HTTP request bodies (a single JSON
// document) and Server-Sent Events streaming responses (one JSON object per
// `data:` line).
package semantic

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/pkg/types"
)

// maxBuffer bounds a single per-(pid,dir) reassembly buffer. When exceeded the
// oldest bytes are dropped (we keep the most-recent tail) so a stream that never
// yields a parseable object cannot grow without limit.
const maxBuffer = 1 << 20 // 1 MiB

// redactThreshold is the string length above which tool-input values are
// replaced with a redacted placeholder when capturePrompts is disabled.
const redactThreshold = 64

// bufKey identifies a reassembly buffer. Each (host pid, connection, direction)
// tuple is an independent plaintext stream; including conn separates concurrent
// TLS connections a process runs, whose HTTP/2 stream ids would otherwise
// collide in one buffer.
type bufKey struct {
	pid  int32
	conn uint64
	dir  types.Direction
}

// Parser is the concrete SemanticParser implementation.
type Parser struct {
	capturePrompts bool
	log            *zap.Logger

	mu    sync.Mutex
	conns map[bufKey]*connState
	// h2pids records pids whose outbound connection was detected as HTTP/2 (via
	// the client preface), so inbound responses for that pid are demuxed as HTTP/2
	// too (the server never sends a preface).
	h2pids map[int32]bool

	// toolStreams accumulates streamed Anthropic tool_use inputs (arriving as
	// input_json_delta fragments) per (pid, HTTP/2 stream, content-block index)
	// until the block stops. Guarded by tsMu since dispatch runs outside mu.
	tsMu        sync.Mutex
	toolStreams map[toolKey]*toolAccum
}

// toolKey identifies an in-flight streamed tool_use accumulation. The stream id
// distinguishes concurrent HTTP/2 responses that reuse content-block indices.
type toolKey struct {
	pid    int32
	conn   uint64
	stream uint32
	idx    int
}

// toolAccum accumulates a streamed tool_use block.
type toolAccum struct {
	id, name, model string
	json            []byte
}

// maxToolJSON bounds a single accumulated streamed tool_use input.
const maxToolJSON = 256 * 1024

// New constructs a Parser. When capturePrompts is false, prompt/assistant text
// and large tool-input string values are redacted to a length+hash placeholder.
func New(capturePrompts bool, log *zap.Logger) *Parser {
	if log == nil {
		log = zap.NewNop()
	}
	return &Parser{
		capturePrompts: capturePrompts,
		log:            log,
		conns:          make(map[bufKey]*connState),
		h2pids:         make(map[int32]bool),
		toolStreams:    make(map[toolKey]*toolAccum),
	}
}

// startToolStream begins accumulating a streamed tool_use block.
func (p *Parser) startToolStream(fc *feedCtx, idx int, id, name, model string) {
	p.tsMu.Lock()
	defer p.tsMu.Unlock()
	p.toolStreams[toolKey{fc.pid, fc.conn, fc.stream, idx}] = &toolAccum{id: id, name: name, model: model}
}

// appendToolStream appends an input_json_delta fragment.
func (p *Parser) appendToolStream(fc *feedCtx, idx int, frag string) {
	if frag == "" {
		return
	}
	p.tsMu.Lock()
	defer p.tsMu.Unlock()
	if a := p.toolStreams[toolKey{fc.pid, fc.conn, fc.stream, idx}]; a != nil && len(a.json) < maxToolJSON {
		a.json = append(a.json, frag...)
	}
}

// finishToolStream emits the completed streamed tool_use, if one was open at idx.
func (p *Parser) finishToolStream(fc *feedCtx, idx int) (types.SemanticEvent, bool) {
	key := toolKey{fc.pid, fc.conn, fc.stream, idx}
	p.tsMu.Lock()
	a := p.toolStreams[key]
	delete(p.toolStreams, key)
	p.tsMu.Unlock()
	if a == nil {
		return types.SemanticEvent{}, false
	}
	var input map[string]any
	if len(a.json) > 0 {
		_ = json.Unmarshal(a.json, &input)
	}
	ev := p.mkEvent(fc, types.SemToolUse, providerAnthropic, a.model)
	ev.ToolUse = &types.ToolUse{
		ID: a.id, Name: a.name,
		Input:       p.redactInput(input),
		IntentClass: classifyIntent(a.name, input),
	}
	if !p.capturePrompts {
		ev.Redacted = true
	}
	return ev, true
}

// intOf is a nil-safe int extraction from a decoded-JSON value.
func intOf(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

// feedCtx carries the per-chunk metadata needed to stamp emitted events. stream
// is the HTTP/2 stream id (0 for HTTP/1), used to keep concurrent responses'
// streamed tool_use accumulation separate.
type feedCtx struct {
	ts     uint64
	pid    int32
	cgroup uint64
	conn   uint64
	stream uint32
	sess   *types.AgentSession
}

// objBatch is a set of complete JSON objects extracted for one HTTP/2 stream.
type objBatch struct {
	stream uint32
	objs   [][]byte
}

// Feed pushes a plaintext chunk into its reassembly buffer and returns any
// semantic events that became fully parseable. HTTP/2 connections are demuxed by
// stream before JSON reassembly; HTTP/1 connections are scanned as a byte stream.
func (p *Parser) Feed(chunk types.SemanticChunk, sess *types.AgentSession) []types.SemanticEvent {
	key := bufKey{pid: chunk.HostPID, conn: chunk.ConnID, dir: chunk.Direction}

	p.mu.Lock()
	c := p.conns[key]
	if c == nil {
		c = newConnState()
		p.conns[key] = c
	}
	batches := p.reassembleLocked(c, key, chunk.Bytes)
	p.mu.Unlock()

	var out []types.SemanticEvent
	for _, b := range batches {
		fc := &feedCtx{ts: chunk.TimestampNS, pid: chunk.HostPID, cgroup: chunk.CgroupID, conn: chunk.ConnID, stream: b.stream, sess: sess}
		for _, o := range b.objs {
			out = append(out, p.dispatch(o, fc)...)
		}
	}
	return out
}

// reassembleLocked routes a chunk's bytes through HTTP/2 demux or HTTP/1 scanning
// and returns the complete JSON objects per stream. Caller holds p.mu.
func (p *Parser) reassembleLocked(c *connState, key bufKey, data []byte) []objBatch {
	if c.mode == 0 {
		c.mode = p.detectModeLocked(key, data)
	}
	if c.mode != 1 {
		// WebSocket: once upgraded, every byte is a frame (Codex realtime transport).
		if c.ws != nil {
			return wsBatch(c.ws.pushWS(data))
		}
		// HTTP/1: single byte-stream buffer, stream id 0.
		buf := append(c.buf, data...)
		if len(buf) > maxBuffer {
			buf = buf[len(buf)-maxBuffer:]
		}
		// Detect a WebSocket upgrade (inbound 101 Switching Protocols, or an
		// outbound `Upgrade: websocket` request). After the handshake header block,
		// the remaining bytes are WebSocket frames.
		if wsUpgradeSeen(buf, key.dir) {
			hdrEnd := bytesIndexCRLFCRLF(buf)
			if hdrEnd < 0 {
				c.buf = append([]byte(nil), buf...)
				return nil // wait for the full handshake header block
			}
			c.ws = &wsConn{}
			c.buf = nil
			return wsBatch(c.ws.pushWS(buf[hdrEnd:]))
		}
		// Inbound responses may be chunked and gzip-compressed (Codex's
		// non-streaming API responses); decode them to plaintext before JSON
		// extraction. Outbound requests and uncompressed SSE fall through unchanged.
		if key.dir == types.DirInbound {
			if decoded, tail, framed := httpBodyDecode(buf); framed {
				c.buf = append([]byte(nil), tail...)
				objs, _ := extractObjects(decoded)
				if len(objs) == 0 {
					return nil
				}
				return []objBatch{{stream: 0, objs: objs}}
			}
		}
		objs, rem := extractObjects(buf)
		c.buf = append([]byte(nil), rem...)
		if len(objs) == 0 {
			return nil
		}
		return []objBatch{{stream: 0, objs: objs}}
	}

	// HTTP/2: strip the client preface (outbound, first chunk) then demux frames.
	if looksLikeH2Preface(data) {
		data = data[len(h2Preface):]
	}
	var batches []objBatch
	for _, sd := range c.pushH2(data) {
		objs, rem := extractObjects(sd.buf)
		c.setStreamRemainder(sd.id, rem)
		if len(objs) > 0 {
			batches = append(batches, objBatch{stream: sd.id, objs: objs})
		}
	}
	return batches
}

// detectModeLocked decides HTTP/2 vs HTTP/1 for a new connection. The outbound
// preface is authoritative and also marks the pid so inbound responses (which
// carry no preface) are demuxed as HTTP/2. Caller holds p.mu.
func (p *Parser) detectModeLocked(key bufKey, data []byte) int {
	if key.dir == types.DirOutbound && looksLikeH2Preface(data) {
		p.h2pids[key.pid] = true
		return 1
	}
	if p.h2pids[key.pid] {
		return 1
	}
	return -1
}

// FeedDB parses a plaintext chunk as a database wire-protocol message for a
// connection to engine (postgres|mysql|mongodb) and returns a SemDBQuery event
// when it is a recognized query. Unlike Feed (JSON reassembly), DB messages are
// parsed per-chunk; a query split across reads is not reassembled.
func (p *Parser) FeedDB(chunk types.SemanticChunk, sess *types.AgentSession, engine string) []types.SemanticEvent {
	q := p.ParseDBQuery(engine, chunk.Bytes)
	if q == nil {
		return nil
	}
	fc := &feedCtx{ts: chunk.TimestampNS, pid: chunk.HostPID, cgroup: chunk.CgroupID, sess: sess}
	ev := p.mkEvent(fc, types.SemDBQuery, "", "")
	ev.DBQuery = q
	return []types.SemanticEvent{ev}
}

// dispatch unmarshals one complete JSON object and routes it to the right
// format parser based on shape and session provider.
func (p *Parser) dispatch(raw []byte, fc *feedCtx) []types.SemanticEvent {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		p.log.Debug("semantic: skipping unparseable object", zap.Error(err), zap.Int("len", len(raw)))
		return nil
	}

	// MCP: JSON-RPC 2.0 envelope.
	if _, ok := m["jsonrpc"]; ok {
		return p.parseMCP(m, fc)
	}

	switch providerForSession(fc.sess) {
	case "anthropic":
		return p.parseAnthropic(m, fc)
	case "openai":
		return p.parseOpenAI(m, fc)
	case "gemini":
		return p.parseGemini(m, fc)
	default:
		// Generic fallback (multi-provider agents like Crush): sniff the object
		// shape. Gemini requests/responses carry `contents`/`candidates`; OpenAI
		// Chat Completions responses carry `choices` or an `object: chat.completion*`
		// tag; a request with both `model` and `messages` is OpenAI-like. Everything
		// else goes to the Anthropic parser, which also understands response
		// `content` blocks and SSE events.
		_, hasContents := m["contents"]
		_, hasCandidates := m["candidates"]
		if hasContents || hasCandidates {
			return p.parseGemini(m, fc)
		}
		if _, ok := m["choices"]; ok {
			return p.parseOpenAI(m, fc)
		}
		if obj, _ := m["object"].(string); len(obj) >= 15 && obj[:15] == "chat.completion" {
			return p.parseOpenAI(m, fc)
		}
		// A top-level `system` alongside `messages` is Anthropic's Messages API
		// request shape (OpenAI carries system as a message role, not top-level).
		_, hasSystem := m["system"]
		_, hasMsgs := m["messages"]
		if hasSystem && hasMsgs {
			return p.parseAnthropic(m, fc)
		}
		if _, hasModel := m["model"]; hasModel && hasMsgs {
			return p.parseOpenAI(m, fc)
		}
		return p.parseAnthropic(m, fc)
	}
}

// parseMCP emits a SemMCP event from a JSON-RPC envelope. Both requests
// (method/params) and results are surfaced.
func (p *Parser) parseMCP(m map[string]any, fc *feedCtx) []types.SemanticEvent {
	ev := p.mkEvent(fc, types.SemMCP, "", "")
	ev.MCPMethod = str(m["method"])
	if params := mapOf(m["params"]); params != nil {
		ev.MCPParams = params
	} else if result := mapOf(m["result"]); result != nil {
		ev.MCPParams = result
	}
	return []types.SemanticEvent{ev}
}

// mkEvent builds a SemanticEvent with common bookkeeping filled in (nil-safe on
// session).
func (p *Parser) mkEvent(fc *feedCtx, kind types.SemanticKind, provider, model string) types.SemanticEvent {
	ev := types.SemanticEvent{
		EventID:     types.NewEventID(),
		TimestampNS: fc.ts,
		Time:        bpf2frame.BootTime(fc.ts),
		HostPID:     fc.pid,
		CgroupID:    fc.cgroup,
		Kind:        kind,
		Provider:    provider,
		Model:       model,
	}
	if fc.sess != nil {
		ev.SessionID = fc.sess.ID
		ev.Agent = fc.sess.Agent
	}
	return ev
}

// textEvent builds a prompt/assistant/tool-result text event applying the
// redaction policy.
func (p *Parser) textEvent(fc *feedCtx, provider, model string, kind types.SemanticKind, text string) types.SemanticEvent {
	ev := p.mkEvent(fc, kind, provider, model)
	ev.Text, ev.Redacted = p.applyText(text)
	return ev
}

// applyText returns the text as-is when capturing prompts, otherwise a redacted
// length+hash placeholder.
func (p *Parser) applyText(text string) (string, bool) {
	if p.capturePrompts {
		return text, false
	}
	return redactPlaceholder(text), true
}

// redactPlaceholder renders a stable, non-reversible summary of a string.
func redactPlaceholder(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("<redacted:%d chars sha=%x>", len(s), sum[:8])
}

// redactInput copies a tool-input map, replacing large string values with a
// redacted placeholder while preserving structure. When capturing prompts the
// input is returned unchanged.
func (p *Parser) redactInput(in map[string]any) map[string]any {
	if p.capturePrompts || in == nil {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok && len(s) > redactThreshold {
			out[k] = redactPlaceholder(s)
			continue
		}
		out[k] = v
	}
	return out
}

// classifyIntent derives a coarse read/write/network/exec class from a tool name
// (and, where useful, its input). Returns "" when unknown.
func classifyIntent(toolName string, _ map[string]any) string {
	switch toolName {
	case "Read", "Grep", "Glob", "LS", "NotebookRead", "list_dir", "read_file", "grep_search", "file_search":
		return "read"
	case "Write", "Edit", "MultiEdit", "NotebookEdit", "create_file", "write_file", "apply_patch", "edit_file":
		return "write"
	case "Bash", "Shell", "Execute", "run_terminal_cmd", "run_command", "shell":
		return "exec"
	case "WebFetch", "WebSearch", "Fetch", "web_search", "browser":
		return "network"
	default:
		return ""
	}
}

// providerForSession maps a session to a provider label ("anthropic"/"openai"),
// nil-safe. An explicit sess.Provider wins over the agent-kind default.
func providerForSession(sess *types.AgentSession) string {
	if sess == nil {
		return ""
	}
	if sess.Provider != "" {
		return sess.Provider
	}
	switch sess.Agent {
	case types.AgentClaudeCode:
		return "anthropic"
	case types.AgentGemini:
		return "gemini"
	}
	// Codex and other multi-provider agents fall through to per-payload sniffing:
	// a Codex install may target the OpenAI or the Anthropic API.
	return ""
}

// extractObjects scans buf for balanced top-level JSON objects. It returns each
// complete `{...}` object (in order) and the trailing remainder to keep
// buffered. Bytes before the first object and non-JSON separators between
// objects are discarded; only a trailing *incomplete* object is preserved.
func extractObjects(buf []byte) (objs [][]byte, remainder []byte) {
	n := len(buf)
	i := 0
	for i < n {
		if buf[i] != '{' {
			i++
			continue
		}
		start := i
		depth := 0
		inStr := false
		esc := false
		end := -1
		for j := start; j < n; j++ {
			c := buf[j]
			if inStr {
				switch {
				case esc:
					esc = false
				case c == '\\':
					esc = true
				case c == '"':
					inStr = false
				}
				continue
			}
			switch c {
			case '"':
				inStr = true
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			// Incomplete object: keep it (and everything after) buffered.
			return objs, buf[start:]
		}
		objs = append(objs, buf[start:end+1])
		i = end + 1
	}
	// All complete objects consumed; no trailing '{' remains, so nothing to keep.
	return objs, nil
}

// str is a nil-safe string type assertion.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// mapOf is a nil-safe map type assertion.
func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
