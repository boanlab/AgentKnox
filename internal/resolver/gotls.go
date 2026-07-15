// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"debug/elf"
	"debug/gosym"

	"golang.org/x/arch/x86/x86asm"

	"github.com/boanlab/agentknox/pkg/types"
)

// Go agents (e.g. Crush) use pure-Go crypto/tls, not OpenSSL/BoringSSL, so the
// plaintext boundary is crypto/tls.(*Conn).Read/.Write. A release binary built
// with -s strips .symtab, but .gopclntab (mandatory, survives -s -w) still
// carries the same names and entry offsets. Capture uses the Go register ABI
// (RBX=slice ptr, RCX=len; RAX=return n); see bpf/semantic.bpf.c.

const (
	keyGoRead  = "go_read"
	keyGoWrite = "go_write"
)

// goTLSSymbols maps logical keys to the Go crypto/tls boundary symbol names.
var goTLSSymbols = map[string]string{
	keyGoRead:  "crypto/tls.(*Conn).Read",
	keyGoWrite: "crypto/tls.(*Conn).Write",
}

// resolveGoTLS resolves the Go crypto/tls boundary. It returns the write/read
// entry offsets plus the RET-instruction offsets inside Read (for the inbound
// return probe). ok is false when the binary is not a symboled Go TLS client.
func resolveGoTLS(f *elf.File) (offs map[string]uint64, readRets []uint64, ok bool) {
	sym := goReadWriteSyms(f)
	if len(sym) == 0 {
		return nil, nil, false
	}
	offs = map[string]uint64{}
	for k, s := range sym {
		if fo, ok := vaddrToFileOffset(f, s.Value); ok {
			offs[k] = fo
		}
	}
	if _, ok := offs[keyGoWrite]; !ok {
		return nil, nil, false // write is the minimum useful boundary
	}
	if r, ok := sym[keyGoRead]; ok {
		if fo, ok := vaddrToFileOffset(f, r.Value); ok {
			readRets = findRETs(f, fo, r.Size)
		}
	}
	return offs, readRets, true
}

// goReadWriteSyms finds the crypto/tls Read/Write symbols (name -> elf.Symbol).
// It prefers .symtab (present in a non-stripped build); when that is absent or
// yields neither name, it falls back to the .gopclntab function table, which a
// -s -w release build still carries.
func goReadWriteSyms(f *elf.File) map[string]elf.Symbol {
	want := map[string]string{}
	for key, name := range goTLSSymbols {
		want[name] = key
	}
	out := map[string]elf.Symbol{}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if key, ok := want[s.Name]; ok && s.Value != 0 {
				out[key] = s
			}
		}
	}
	if len(out) == 0 {
		return goReadWriteSymsFromPcln(f, want)
	}
	return out
}

// goReadWriteSymsFromPcln recovers the crypto/tls boundary functions from the
// Go runtime's .gopclntab, which carries every function's name, entry, and end
// even when .symtab has been stripped (-s). Entry/End are link-time virtual
// addresses; the caller converts them to file offsets as it does for .symtab
// symbols.
func goReadWriteSymsFromPcln(f *elf.File, want map[string]string) map[string]elf.Symbol {
	sec := f.Section(".gopclntab")
	text := f.Section(".text")
	if sec == nil || text == nil {
		return nil
	}
	data, err := sec.Data()
	if err != nil || len(data) == 0 {
		return nil
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil || tab == nil {
		return nil
	}
	out := map[string]elf.Symbol{}
	for name, key := range want {
		if fn := tab.LookupFunc(name); fn != nil && fn.Entry != 0 {
			out[key] = elf.Symbol{Name: name, Value: fn.Entry, Size: fn.End - fn.Entry}
		}
	}
	return out
}

// findRETs disassembles a function [funcFileOff, funcFileOff+size) and returns
// the file offsets of its RET instructions.
func findRETs(f *elf.File, funcFileOff, size uint64) []uint64 {
	if size == 0 {
		return nil
	}
	text := f.Section(".text")
	if text == nil {
		return nil
	}
	data, err := text.Data()
	if err != nil {
		return nil
	}
	if funcFileOff < text.Offset {
		return nil
	}
	start := int(funcFileOff - text.Offset)
	end := start + int(size)
	if start < 0 || end > len(data) {
		return nil
	}
	var rets []uint64
	for pos := start; pos < end; {
		inst, err := x86asm.Decode(data[pos:end], 64)
		if err != nil || inst.Len == 0 {
			pos++ // resync on undecodable bytes (jump tables, padding)
			continue
		}
		if inst.Op == x86asm.RET {
			rets = append(rets, text.Offset+uint64(pos))
		}
		pos += inst.Len
	}
	return rets
}

// applyGoTLS fills the plan from a resolved Go crypto/tls boundary.
func (r *Resolver) applyGoTLS(plan *types.AttachPlan, offs map[string]uint64, readRets []uint64) {
	for k, v := range offs {
		plan.Offsets[k] = v
	}
	plan.GoReadRets = readRets
	plan.Boundary = types.BoundaryGoTLS
	plan.Tier = types.TierSymtab
	plan.Confidence = 0.95
	// Full when both directions are hookable; write-only (no read rets) is degraded.
	_, hasWrite := offs[keyGoWrite]
	if hasWrite && len(readRets) > 0 {
		plan.Coverage = types.CoverageFull
	} else if hasWrite {
		plan.Coverage = types.CoverageDegraded
	} else {
		plan.Coverage = types.CoverageNone
	}
}
