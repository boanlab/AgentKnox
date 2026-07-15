// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"encoding/json"

	"github.com/boanlab/agentknox/pkg/types"
)

const (
	providerAnthropic = "anthropic"
	providerOpenAI    = "openai"
	providerGemini    = "gemini"
)

// parseAnthropic handles the Anthropic Messages API used by Claude Code, in all
// three shapes it appears on the wire: outbound request bodies (`messages`,
// `system`, `model`, `tools`), inbound full response bodies (`content` blocks),
// and inbound SSE streaming events (`type: content_block_*` / `message_*`).
func (p *Parser) parseAnthropic(m map[string]any, fc *feedCtx) []types.SemanticEvent {
	model := str(m["model"])
	var out []types.SemanticEvent

	// SSE streaming event?
	if t, ok := m["type"].(string); ok {
		switch t {
		case "content_block_start":
			if cb := mapOf(m["content_block"]); cb != nil && str(cb["type"]) == "tool_use" {
				// Streaming tool_use: the input arrives later via input_json_delta,
				// so start accumulating and emit at content_block_stop.
				p.startToolStream(fc, intOf(m["index"]), str(cb["id"]), str(cb["name"]), model)
			}
			return out
		case "content_block_delta":
			if d := mapOf(m["delta"]); d != nil {
				switch str(d["type"]) {
				case "text_delta":
					if txt := str(d["text"]); txt != "" {
						out = append(out, p.textEvent(fc, providerAnthropic, model, types.SemAssistant, txt))
					}
				case "input_json_delta":
					p.appendToolStream(fc, intOf(m["index"]), str(d["partial_json"]))
				}
			}
			return out
		case "content_block_stop":
			if ev, ok := p.finishToolStream(fc, intOf(m["index"])); ok {
				out = append(out, ev)
			}
			return out
		case "message_start":
			if msg := mapOf(m["message"]); msg != nil {
				out = append(out, p.anthropicUsage(fc, model, mapOf(msg["usage"]))...)
			}
			return out
		case "message_delta":
			out = append(out, p.anthropicUsage(fc, model, mapOf(m["usage"]))...)
			return out
		case "message_stop", "ping", "error":
			return out
		}
		// Unknown `type` value: fall through to structural detection.
	}

	// Outbound request: `messages` array (+ optional `system`).
	if msgs, ok := m["messages"].([]any); ok {
		if sysTxt := anthropicText(m["system"]); sysTxt != "" {
			out = append(out, p.textEvent(fc, providerAnthropic, model, types.SemPrompt, sysTxt))
		}
		for _, mi := range msgs {
			mm := mapOf(mi)
			if mm == nil {
				continue
			}
			out = append(out, p.anthropicBlocks(fc, model, str(mm["role"]), mm["content"])...)
		}
		return out
	}

	// Inbound full response: top-level `content` blocks.
	if _, ok := m["content"]; ok {
		role := str(m["role"])
		if role == "" {
			role = "assistant"
		}
		out = append(out, p.anthropicBlocks(fc, model, role, m["content"])...)
		return out
	}

	return out
}

// anthropicBlocks turns a message `content` value (string or block array) into
// events, honoring the message role.
func (p *Parser) anthropicBlocks(fc *feedCtx, model, role string, content any) []types.SemanticEvent {
	var out []types.SemanticEvent

	if s, ok := content.(string); ok {
		if s == "" {
			return out
		}
		kind := types.SemAssistant
		if role == "user" {
			kind = types.SemPrompt
		}
		return append(out, p.textEvent(fc, providerAnthropic, model, kind, s))
	}

	blocks, ok := content.([]any)
	if !ok {
		return out
	}
	for _, bi := range blocks {
		b := mapOf(bi)
		if b == nil {
			continue
		}
		switch str(b["type"]) {
		case "text":
			if txt := str(b["text"]); txt != "" {
				kind := types.SemAssistant
				if role == "user" {
					kind = types.SemPrompt
				}
				out = append(out, p.textEvent(fc, providerAnthropic, model, kind, txt))
			}
		case "tool_use":
			out = append(out, p.anthropicToolUse(fc, model, b))
		case "tool_result":
			out = append(out, p.anthropicToolResult(fc, model, b))
		}
	}
	return out
}

// anthropicUsage emits a SemUsage event carrying token counts, if present.
func (p *Parser) anthropicUsage(fc *feedCtx, model string, u map[string]any) []types.SemanticEvent {
	if u == nil {
		return nil
	}
	in, out := intOf(u["input_tokens"]), intOf(u["output_tokens"])
	if in == 0 && out == 0 {
		return nil
	}
	ev := p.mkEvent(fc, types.SemUsage, providerAnthropic, model)
	ev.TokensIn = in
	ev.TokensOut = out
	return []types.SemanticEvent{ev}
}

func (p *Parser) anthropicToolUse(fc *feedCtx, model string, b map[string]any) types.SemanticEvent {
	name := str(b["name"])
	input := mapOf(b["input"])
	ev := p.mkEvent(fc, types.SemToolUse, providerAnthropic, model)
	ev.ToolUse = &types.ToolUse{
		ID:          str(b["id"]),
		Name:        name,
		Input:       p.redactInput(input),
		IntentClass: classifyIntent(name, input),
	}
	if !p.capturePrompts {
		ev.Redacted = true
	}
	return ev
}

// anthropicToolResult builds a SemToolResult event from a tool_result content
// block (which appears in a subsequent request's user message).
func (p *Parser) anthropicToolResult(fc *feedCtx, model string, b map[string]any) types.SemanticEvent {
	ev := p.mkEvent(fc, types.SemToolResult, providerAnthropic, model)
	ev.ToolResult = &types.ToolUse{ID: str(b["tool_use_id"])}
	if txt := anthropicText(b["content"]); txt != "" {
		ev.Text, ev.Redacted = p.applyText(txt)
	}
	return ev
}

// anthropicText flattens a content value (string, or array of blocks) to its
// concatenated text.
func anthropicText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var s string
		for _, bi := range c {
			b := mapOf(bi)
			if b == nil {
				continue
			}
			if t := str(b["text"]); t != "" {
				if s != "" {
					s += "\n"
				}
				s += t
			}
		}
		return s
	}
	return ""
}

// parseOpenAI handles the OpenAI Chat Completions and Responses APIs used by
// Codex: request `messages`/`input` arrays, response `choices[].message` and
// `output[]` items, with `tool_calls`/`function_call` for tool invocations.
func (p *Parser) parseOpenAI(m map[string]any, fc *feedCtx) []types.SemanticEvent {
	model := str(m["model"])
	var out []types.SemanticEvent

	for _, key := range []string{"messages", "input"} {
		if arr, ok := m[key].([]any); ok {
			for _, it := range arr {
				if msg := mapOf(it); msg != nil {
					out = append(out, p.openaiMessage(fc, model, msg)...)
				}
			}
		}
	}

	if arr, ok := m["choices"].([]any); ok {
		for _, c := range arr {
			cm := mapOf(c)
			if cm == nil {
				continue
			}
			// Non-streaming completion: a full `message` object.
			if msg := mapOf(cm["message"]); msg != nil {
				out = append(out, p.openaiMessage(fc, model, msg)...)
			}
			// Streaming completion (`chat.completion.chunk`): each event carries a
			// `delta` fragment. Mirror the Anthropic text_delta handling by
			// emitting an assistant event per content fragment.
			if d := mapOf(cm["delta"]); d != nil {
				if txt := openaiText(d["content"]); txt != "" {
					out = append(out, p.textEvent(fc, providerOpenAI, model, types.SemAssistant, txt))
				}
			}
		}
	}

	if arr, ok := m["output"].([]any); ok {
		for _, it := range arr {
			out = append(out, p.openaiOutputItem(fc, model, mapOf(it))...)
		}
	}

	return out
}

// openaiMessage turns one chat/responses message object into events.
func (p *Parser) openaiMessage(fc *feedCtx, model string, msg map[string]any) []types.SemanticEvent {
	var out []types.SemanticEvent
	role := str(msg["role"])
	text := openaiText(msg["content"])

	switch role {
	case "tool":
		ev := p.mkEvent(fc, types.SemToolResult, providerOpenAI, model)
		ev.ToolResult = &types.ToolUse{ID: str(msg["tool_call_id"])}
		if text != "" {
			ev.Text, ev.Redacted = p.applyText(text)
		}
		out = append(out, ev)
	case "assistant":
		if text != "" {
			out = append(out, p.textEvent(fc, providerOpenAI, model, types.SemAssistant, text))
		}
	default: // user, system, developer
		if text != "" {
			out = append(out, p.textEvent(fc, providerOpenAI, model, types.SemPrompt, text))
		}
	}

	if calls, ok := msg["tool_calls"].([]any); ok {
		for _, ci := range calls {
			c := mapOf(ci)
			if c == nil {
				continue
			}
			fn := mapOf(c["function"])
			name := str(fn["name"])
			input := parseArgs(fn["arguments"])
			ev := p.mkEvent(fc, types.SemToolUse, providerOpenAI, model)
			ev.ToolUse = &types.ToolUse{
				ID:          str(c["id"]),
				Name:        name,
				Input:       p.redactInput(input),
				IntentClass: classifyIntent(name, input),
			}
			if !p.capturePrompts {
				ev.Redacted = true
			}
			out = append(out, ev)
		}
	}
	return out
}

// openaiOutputItem handles a Responses-API `output[]` item (function_call or
// message).
func (p *Parser) openaiOutputItem(fc *feedCtx, model string, it map[string]any) []types.SemanticEvent {
	if it == nil {
		return nil
	}
	switch str(it["type"]) {
	case "function_call":
		name := str(it["name"])
		input := parseArgs(it["arguments"])
		ev := p.mkEvent(fc, types.SemToolUse, providerOpenAI, model)
		id := str(it["call_id"])
		if id == "" {
			id = str(it["id"])
		}
		ev.ToolUse = &types.ToolUse{
			ID:          id,
			Name:        name,
			Input:       p.redactInput(input),
			IntentClass: classifyIntent(name, input),
		}
		if !p.capturePrompts {
			ev.Redacted = true
		}
		return []types.SemanticEvent{ev}
	case "message":
		if txt := openaiText(it["content"]); txt != "" {
			return []types.SemanticEvent{p.textEvent(fc, providerOpenAI, model, types.SemAssistant, txt)}
		}
	}
	return nil
}

// openaiText flattens a message `content` value (string, or array of typed text
// parts) to its concatenated text.
func openaiText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var s string
		for _, pi := range c {
			part := mapOf(pi)
			if part == nil {
				continue
			}
			switch str(part["type"]) {
			case "text", "input_text", "output_text":
				if t := str(part["text"]); t != "" {
					if s != "" {
						s += "\n"
					}
					s += t
				}
			}
		}
		return s
	}
	return ""
}

// parseArgs decodes an OpenAI tool-call `arguments` value, which is a JSON
// string (Chat API) or an object (some Responses payloads).
func parseArgs(v any) map[string]any {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil
		}
		var mm map[string]any
		if json.Unmarshal([]byte(a), &mm) == nil {
			return mm
		}
	case map[string]any:
		return a
	}
	return nil
}

// parseGemini handles the Google Gemini `generateContent`/`streamGenerateContent`
// API used by Gemini CLI. Requests carry a `contents` array (+ optional
// `systemInstruction`); responses carry `candidates[].content`. Both wrap text,
// tool calls and tool results in typed `parts`. The model name lives in the URL,
// not the body, so events carry an empty model.
func (p *Parser) parseGemini(m map[string]any, fc *feedCtx) []types.SemanticEvent {
	var out []types.SemanticEvent

	// Outbound request: system instruction then the conversation turns.
	if si := mapOf(m["systemInstruction"]); si != nil {
		if txt := geminiText(si["parts"]); txt != "" {
			out = append(out, p.textEvent(fc, providerGemini, "", types.SemPrompt, txt))
		}
	}
	if arr, ok := m["contents"].([]any); ok {
		for _, ci := range arr {
			c := mapOf(ci)
			if c == nil {
				continue
			}
			out = append(out, p.geminiParts(fc, str(c["role"]), c["parts"])...)
		}
	}

	// Inbound response: one or more candidates, each a model turn.
	if arr, ok := m["candidates"].([]any); ok {
		for _, ci := range arr {
			c := mapOf(ci)
			if c == nil {
				continue
			}
			content := mapOf(c["content"])
			role := str(content["role"])
			if role == "" {
				role = "model"
			}
			out = append(out, p.geminiParts(fc, role, content["parts"])...)
		}
	}

	if um := mapOf(m["usageMetadata"]); um != nil {
		in, gen := intOf(um["promptTokenCount"]), intOf(um["candidatesTokenCount"])
		if in != 0 || gen != 0 {
			ev := p.mkEvent(fc, types.SemUsage, providerGemini, "")
			ev.TokensIn, ev.TokensOut = in, gen
			out = append(out, ev)
		}
	}
	return out
}

// geminiParts turns a Gemini `parts` array into events, honoring the turn role
// ("user" → prompt, "model" → assistant). A part is text, a functionCall
// (tool_use) or a functionResponse (tool_result).
func (p *Parser) geminiParts(fc *feedCtx, role string, parts any) []types.SemanticEvent {
	arr, ok := parts.([]any)
	if !ok {
		return nil
	}
	kind := types.SemAssistant
	if role == "user" {
		kind = types.SemPrompt
	}
	var out []types.SemanticEvent
	for _, pi := range arr {
		part := mapOf(pi)
		if part == nil {
			continue
		}
		switch {
		case part["functionCall"] != nil:
			fcMap := mapOf(part["functionCall"])
			name := str(fcMap["name"])
			input := mapOf(fcMap["args"])
			ev := p.mkEvent(fc, types.SemToolUse, providerGemini, "")
			ev.ToolUse = &types.ToolUse{
				Name:        name,
				Input:       p.redactInput(input),
				IntentClass: classifyIntent(name, input),
			}
			if !p.capturePrompts {
				ev.Redacted = true
			}
			out = append(out, ev)
		case part["functionResponse"] != nil:
			frMap := mapOf(part["functionResponse"])
			ev := p.mkEvent(fc, types.SemToolResult, providerGemini, "")
			ev.ToolResult = &types.ToolUse{Name: str(frMap["name"])}
			if resp := mapOf(frMap["response"]); resp != nil {
				if txt := str(resp["output"]); txt != "" {
					ev.Text, ev.Redacted = p.applyText(txt)
				}
			}
			out = append(out, ev)
		default:
			if txt := str(part["text"]); txt != "" {
				out = append(out, p.textEvent(fc, providerGemini, "", kind, txt))
			}
		}
	}
	return out
}

// geminiText flattens a `parts` array to its concatenated text (for
// systemInstruction, which has no role).
func geminiText(parts any) string {
	arr, ok := parts.([]any)
	if !ok {
		return ""
	}
	var s string
	for _, pi := range arr {
		part := mapOf(pi)
		if part == nil {
			continue
		}
		if t := str(part["text"]); t != "" {
			if s != "" {
				s += "\n"
			}
			s += t
		}
	}
	return s
}
