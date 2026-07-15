// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"debug/elf"

	"golang.org/x/arch/x86/x86asm"
)

// T6 recovers an unnamed boundary function by cross-reference: when a caller
// whose offset IS known (a resolved export that wraps the stripped boundary) is
// available, disassemble it and follow its direct CALL to the target. This
// completes a resolution the symbol tables left partial — it needs at least one
// caller anchor, so it is a no-op for a fully-stripped binary with no usable
// symbols (the fundamental limit).

// disasmFollowCall disassembles up to maxInsns instructions of x86-64 code
// starting at startFileOff (a file offset inside the .text section whose bytes
// begin at textFileOff) and returns the file offset of the first direct near
// CALL target, stopping at a RET.
func disasmFollowCall(text []byte, textFileOff, startFileOff uint64, maxInsns int) (uint64, bool) {
	if startFileOff < textFileOff {
		return 0, false
	}
	pos := int(startFileOff - textFileOff)
	if pos < 0 || pos >= len(text) {
		return 0, false
	}
	for i := 0; i < maxInsns && pos < len(text); i++ {
		inst, err := x86asm.Decode(text[pos:], 64)
		if err != nil || inst.Len == 0 {
			return 0, false
		}
		switch inst.Op {
		case x86asm.CALL:
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				// A Rel is relative to the end of the instruction.
				target := int64(pos) + int64(inst.Len) + int64(rel)
				if target >= 0 && target < int64(len(text)) {
					return textFileOff + uint64(target), true
				}
			}
		case x86asm.RET:
			return 0, false
		}
		pos += inst.Len
	}
	return 0, false
}

// resolveXref recovers boundary offsets by following the first direct CALL out of
// each caller anchor. anchors maps a logical key to the file offset of a known
// caller of that key's boundary.
func resolveXref(f *elf.File, anchors map[string]uint64) (map[string]uint64, bool) {
	if len(anchors) == 0 {
		return nil, false
	}
	text := f.Section(".text")
	if text == nil {
		return nil, false
	}
	data, err := text.Data()
	if err != nil {
		return nil, false
	}
	out := map[string]uint64{}
	for key, callerOff := range anchors {
		if tgt, ok := disasmFollowCall(data, text.Offset, callerOff, 32); ok {
			out[key] = tgt
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
