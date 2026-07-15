// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

func claudeSession() *types.AgentSession {
	return &types.AgentSession{ID: "sess-1", Agent: types.AgentClaudeCode}
}

func codexSession() *types.AgentSession {
	return &types.AgentSession{ID: "sess-2", Agent: types.AgentCodex}
}

// crushSession has no provider default, exercising the generic dispatch fallback.
func crushSession() *types.AgentSession {
	return &types.AgentSession{ID: "sess-3", Agent: types.AgentCrush}
}

func geminiSession() *types.AgentSession {
	return &types.AgentSession{ID: "sess-4", Agent: types.AgentGemini}
}

func feed(p *Parser, sess *types.AgentSession, dir types.Direction, body string) []types.SemanticEvent {
	return p.Feed(types.SemanticChunk{
		TimestampNS: 1_700_000_000_000_000_000,
		HostPID:     4242,
		CgroupID:    99,
		Direction:   dir,
		Bytes:       []byte(body),
	}, sess)
}

// firstOfKind returns the first event of the given kind, or a zero value.
func firstOfKind(evs []types.SemanticEvent, k types.SemanticKind) (types.SemanticEvent, bool) {
	for _, e := range evs {
		if e.Kind == k {
			return e, true
		}
	}
	return types.SemanticEvent{}, false
}

func TestAnthropicRequestToolUse(t *testing.T) {
	// An outbound Anthropic Messages request whose prior assistant turn issued a
	// tool_use, and whose latest user turn carries the matching tool_result.
	body := `POST /v1/messages HTTP/1.1
Host: api.anthropic.com
Content-Type: application/json

{"model":"claude-3-5-sonnet","system":"You are a helpful assistant.","messages":[` +
		`{"role":"user","content":"read the config file"},` +
		`{"role":"assistant","content":[{"type":"text","text":"On it."},{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/etc/app.conf"}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"key=value"}]}` +
		`],"tools":[{"name":"Read"}]}`

	p := New(true, nil)
	evs := feed(p, claudeSession(), types.DirOutbound, body)

	tu, ok := firstOfKind(evs, types.SemToolUse)
	if !ok {
		t.Fatalf("expected a SemToolUse event, got %+v", kinds(evs))
	}
	if tu.ToolUse == nil || tu.ToolUse.Name != "Read" {
		t.Fatalf("expected tool name Read, got %+v", tu.ToolUse)
	}
	if tu.ToolUse.IntentClass != "read" {
		t.Errorf("expected intent class read, got %q", tu.ToolUse.IntentClass)
	}
	if tu.ToolUse.ID != "toolu_1" {
		t.Errorf("expected tool id toolu_1, got %q", tu.ToolUse.ID)
	}
	if tu.Provider != "anthropic" {
		t.Errorf("expected provider anthropic, got %q", tu.Provider)
	}
	if tu.Model != "claude-3-5-sonnet" {
		t.Errorf("expected model set, got %q", tu.Model)
	}
	if tu.SessionID != "sess-1" || tu.Agent != types.AgentClaudeCode {
		t.Errorf("session metadata not propagated: %q %q", tu.SessionID, tu.Agent)
	}

	// Prompt (user text) present.
	if pr, ok := firstOfKind(evs, types.SemPrompt); !ok {
		t.Error("expected a SemPrompt event")
	} else if pr.Text == "" {
		t.Error("expected prompt text captured")
	}

	// Tool result linked back to the tool_use id.
	tr, ok := firstOfKind(evs, types.SemToolResult)
	if !ok {
		t.Fatal("expected a SemToolResult event")
	}
	if tr.ToolResult == nil || tr.ToolResult.ID != "toolu_1" {
		t.Errorf("expected tool_result linked to toolu_1, got %+v", tr.ToolResult)
	}
}

func TestAnthropicSSEDelta(t *testing.T) {
	// A streaming SSE `data:` line carrying an assistant text delta.
	sse := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n"

	p := New(true, nil)
	evs := feed(p, claudeSession(), types.DirInbound, sse)

	as, ok := firstOfKind(evs, types.SemAssistant)
	if !ok {
		t.Fatalf("expected a SemAssistant event, got %+v", kinds(evs))
	}
	if as.Text != "Hello" {
		t.Errorf("expected assistant text Hello, got %q", as.Text)
	}
}

func TestAnthropicSSEToolUseStreaming(t *testing.T) {
	// Streaming tool_use: content_block_start begins the block, input arrives as
	// input_json_delta fragments, and the full tool_use is emitted at stop.
	sse := `data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_9","name":"Bash"}}` + "\n\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}` + "\n\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"ls\"}"}}` + "\n\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n"
	p := New(true, nil)
	evs := feed(p, claudeSession(), types.DirInbound, sse)
	tu, ok := firstOfKind(evs, types.SemToolUse)
	if !ok {
		t.Fatalf("expected SemToolUse from streamed SSE, got %+v", kinds(evs))
	}
	if tu.ToolUse.Name != "Bash" || tu.ToolUse.IntentClass != "exec" {
		t.Errorf("expected Bash/exec, got %s/%s", tu.ToolUse.Name, tu.ToolUse.IntentClass)
	}
	if tu.ToolUse.Input["command"] != "ls" {
		t.Errorf("expected reassembled input command=ls, got %v", tu.ToolUse.Input)
	}
}

func TestFragmentedReassembly(t *testing.T) {
	// A single JSON body split across two chunks must reassemble.
	p := New(true, nil)
	part1 := `{"model":"claude-x","messages":[{"role":"user","content":"hel`
	part2 := `lo world"}]}`

	if evs := feed(p, claudeSession(), types.DirOutbound, part1); len(evs) != 0 {
		t.Fatalf("expected no events from partial chunk, got %d", len(evs))
	}
	evs := feed(p, claudeSession(), types.DirOutbound, part2)
	pr, ok := firstOfKind(evs, types.SemPrompt)
	if !ok {
		t.Fatalf("expected SemPrompt after reassembly, got %+v", kinds(evs))
	}
	if pr.Text != "hello world" {
		t.Errorf("expected reassembled text, got %q", pr.Text)
	}
}

func TestOpenAIChatToolCall(t *testing.T) {
	body := `{"model":"gpt-5","messages":[` +
		`{"role":"user","content":"list the directory"},` +
		`{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}` +
		`]}`
	p := New(true, nil)
	evs := feed(p, codexSession(), types.DirOutbound, body)
	tu, ok := firstOfKind(evs, types.SemToolUse)
	if !ok {
		t.Fatalf("expected SemToolUse, got %+v", kinds(evs))
	}
	if tu.Provider != "openai" {
		t.Errorf("expected provider openai, got %q", tu.Provider)
	}
	if tu.ToolUse.Name != "Bash" || tu.ToolUse.IntentClass != "exec" {
		t.Errorf("expected Bash/exec, got %+v", tu.ToolUse)
	}
	if cmd, _ := tu.ToolUse.Input["command"].(string); cmd != "ls" {
		t.Errorf("expected parsed arguments command=ls, got %q", cmd)
	}
}

// TestCrushOpenAIStreaming covers a multi-provider agent (no provider default)
// whose provider speaks the OpenAI Chat Completions streaming format: the generic
// dispatch fallback must route `choices`-bearing objects to the OpenAI parser,
// and the parser must emit an assistant event from a `delta` fragment.
func TestCrushOpenAIStreaming(t *testing.T) {
	p := New(true, nil)
	chunks := []string{
		`{"id":"gen-1","object":"chat.completion.chunk","model":"claude-x","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		`{"id":"gen-1","object":"chat.completion.chunk","model":"claude-x","choices":[{"index":0,"delta":{"content":"Hello"}}]}`,
		`{"id":"gen-1","object":"chat.completion.chunk","model":"claude-x","choices":[{"index":0,"delta":{"content":" world"}}]}`,
	}
	var text string
	for _, c := range chunks {
		for _, ev := range feed(p, crushSession(), types.DirInbound, c) {
			if ev.Kind == types.SemAssistant {
				if ev.Provider != "openai" {
					t.Errorf("expected provider openai, got %q", ev.Provider)
				}
				text += ev.Text
			}
		}
	}
	if text != "Hello world" {
		t.Errorf("expected reassembled assistant text %q, got %q", "Hello world", text)
	}
}

// TestCrushOpenAIRequest covers the outbound side of a multi-provider agent: an
// OpenAI-format request (model + messages) routes to the OpenAI parser.
func TestCrushOpenAIRequest(t *testing.T) {
	body := `{"model":"claude-x","messages":[{"role":"user","content":"hi there"}]}`
	p := New(true, nil)
	evs := feed(p, crushSession(), types.DirOutbound, body)
	ev, ok := firstOfKind(evs, types.SemPrompt)
	if !ok {
		t.Fatalf("expected SemPrompt, got %+v", kinds(evs))
	}
	if ev.Provider != "openai" || ev.Text != "hi there" {
		t.Errorf("expected openai prompt %q, got provider=%q text=%q", "hi there", ev.Provider, ev.Text)
	}
}

// TestGeminiRequest covers the outbound Gemini `generateContent` body: a system
// instruction plus a user turn become prompt events.
func TestGeminiRequest(t *testing.T) {
	body := `{"systemInstruction":{"parts":[{"text":"You are Gemini"}]},` +
		`"contents":[{"role":"user","parts":[{"text":"what is 2+2"}]}]}`
	p := New(true, nil)
	evs := feed(p, geminiSession(), types.DirOutbound, body)
	var texts []string
	for _, e := range evs {
		if e.Kind == types.SemPrompt {
			if e.Provider != "gemini" {
				t.Errorf("expected provider gemini, got %q", e.Provider)
			}
			texts = append(texts, e.Text)
		}
	}
	if len(texts) != 2 || texts[0] != "You are Gemini" || texts[1] != "what is 2+2" {
		t.Errorf("expected system+user prompts, got %v", texts)
	}
}

// TestGeminiResponseAndToolCall covers the inbound `candidates` response: a model
// text part is an assistant event, a functionCall part is a tool_use.
func TestGeminiResponseAndToolCall(t *testing.T) {
	p := New(true, nil)
	text := `{"candidates":[{"content":{"role":"model","parts":[{"text":"The answer is 4."}]}}]}`
	if ev, ok := firstOfKind(feed(p, geminiSession(), types.DirInbound, text), types.SemAssistant); !ok {
		t.Fatalf("expected SemAssistant from candidates")
	} else if ev.Text != "The answer is 4." || ev.Provider != "gemini" {
		t.Errorf("unexpected assistant event: %+v", ev)
	}

	call := `{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"ls"}}}]}}]}`
	ev, ok := firstOfKind(feed(New(true, nil), geminiSession(), types.DirInbound, call), types.SemToolUse)
	if !ok {
		t.Fatalf("expected SemToolUse from functionCall")
	}
	if ev.ToolUse.Name != "run_shell_command" {
		t.Errorf("expected tool name run_shell_command, got %q", ev.ToolUse.Name)
	}
	if cmd, _ := ev.ToolUse.Input["command"].(string); cmd != "ls" {
		t.Errorf("expected command=ls, got %q", cmd)
	}
}

func TestMCPJSONRPC(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`
	p := New(true, nil)
	evs := feed(p, nil, types.DirOutbound, body)
	ev, ok := firstOfKind(evs, types.SemMCP)
	if !ok {
		t.Fatalf("expected SemMCP, got %+v", kinds(evs))
	}
	if ev.MCPMethod != "tools/call" {
		t.Errorf("expected method tools/call, got %q", ev.MCPMethod)
	}
	if ev.MCPParams["name"] != "search" {
		t.Errorf("expected params.name search, got %+v", ev.MCPParams)
	}
}

func TestRedactionDisabled(t *testing.T) {
	body := `{"model":"claude-x","messages":[{"role":"user","content":"my secret prompt text"}]}`
	p := New(false, nil) // capturePrompts=false
	evs := feed(p, claudeSession(), types.DirOutbound, body)
	pr, ok := firstOfKind(evs, types.SemPrompt)
	if !ok {
		t.Fatalf("expected SemPrompt, got %+v", kinds(evs))
	}
	if !pr.Redacted {
		t.Error("expected event marked redacted")
	}
	if !strings.HasPrefix(pr.Text, "<redacted:") {
		t.Errorf("expected redacted placeholder, got %q", pr.Text)
	}
	if strings.Contains(pr.Text, "secret") {
		t.Errorf("redacted text leaked content: %q", pr.Text)
	}
}

func TestRedactLargeToolInput(t *testing.T) {
	big := strings.Repeat("A", 200)
	body := `{"model":"claude-x","messages":[{"role":"assistant","content":[` +
		`{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/x","content":"` + big + `"}}]}]}`
	p := New(false, nil)
	evs := feed(p, claudeSession(), types.DirOutbound, body)
	tu, ok := firstOfKind(evs, types.SemToolUse)
	if !ok {
		t.Fatalf("expected SemToolUse, got %+v", kinds(evs))
	}
	// Structure preserved, small value kept, large value redacted.
	if tu.ToolUse.Input["file_path"] != "/x" {
		t.Errorf("expected small value preserved, got %+v", tu.ToolUse.Input["file_path"])
	}
	content, _ := tu.ToolUse.Input["content"].(string)
	if !strings.HasPrefix(content, "<redacted:") {
		t.Errorf("expected large value redacted, got %q", content)
	}
}

func TestParseDBQueryPostgres(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		wantOp  string
		wantTbl string
		wantWhr bool
	}{
		{"select", "SELECT * FROM users WHERE id = 1", "SELECT", "users", true},
		{"insert", "INSERT INTO accounts (id) VALUES (5)", "INSERT", "accounts", false},
		{"update", "UPDATE sessions SET state='x' WHERE id=2", "UPDATE", "sessions", true},
		{"delete", "DELETE FROM logs", "DELETE", "logs", false},
	}
	p := New(true, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := pgSimpleQuery(tc.sql)
			q := p.ParseDBQuery("postgres", buf)
			if q == nil {
				t.Fatal("expected a DBQuery, got nil")
			}
			if q.Op != tc.wantOp {
				t.Errorf("op: want %q got %q", tc.wantOp, q.Op)
			}
			if q.Table != tc.wantTbl {
				t.Errorf("table: want %q got %q", tc.wantTbl, q.Table)
			}
			if q.HasWhere != tc.wantWhr {
				t.Errorf("hasWhere: want %v got %v", tc.wantWhr, q.HasWhere)
			}
			if q.Engine != "postgres" {
				t.Errorf("engine: want postgres got %q", q.Engine)
			}
		})
	}
}

func TestParseDBQueryRedactsLiteral(t *testing.T) {
	p := New(false, nil)
	q := p.ParseDBQuery("postgres", pgSimpleQuery("SELECT * FROM t WHERE name = 'alice'"))
	if q == nil {
		t.Fatal("expected DBQuery")
	}
	if strings.Contains(q.StmtRedact, "alice") {
		t.Errorf("expected literal redacted, got %q", q.StmtRedact)
	}
}

func TestParseDBQueryStubs(t *testing.T) {
	p := New(true, nil)
	if q := p.ParseDBQuery("mysql", []byte{0x03, 'S'}); q != nil {
		t.Errorf("expected nil (stub) for mysql, got %+v", q)
	}
	if q := p.ParseDBQuery("mongodb", []byte{0x00}); q != nil {
		t.Errorf("expected nil (stub) for mongodb, got %+v", q)
	}
}

// pgSimpleQuery builds a PostgreSQL Simple Query ('Q') wire message.
func pgSimpleQuery(sql string) []byte {
	body := append([]byte(sql), 0x00) // null-terminated
	out := make([]byte, 1+4+len(body))
	out[0] = 'Q'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

func kinds(evs []types.SemanticEvent) []types.SemanticKind {
	ks := make([]types.SemanticKind, len(evs))
	for i, e := range evs {
		ks[i] = e.Kind
	}
	return ks
}
