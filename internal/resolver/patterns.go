// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// T5 recovers a boundary function in a stripped binary (stripped Bun/Node/
// BoringSSL) by matching the function-prologue byte pattern of an open-source
// reference build of the same TLS provider, then verifying uniqueness. The
// signatures themselves are DATA — derived offline from a reference build and
// stored in a signature file — so new stripped builds can be supported without
// recompiling. The scanner and its verification are the mechanism here.

// patByte is one byte of a pattern: a fixed value, or a wildcard that matches any
// byte (used for relative displacements / addresses that vary between builds).
type patByte struct {
	val      byte
	wildcard bool
}

// signature is a prologue pattern for one boundary function of one provider.
type signature struct {
	provider string
	key      string // logical offset key (read|write|handshake|aead_open|aead_seal)
	pattern  []patByte
	refOff   uint64 // reference-build file offset, for inter-function distance checks
}

// parsePattern parses a space-separated hex pattern where "??" is a wildcard,
// e.g. "55 48 89 e5 ?? ?? e8" → 7 bytes, positions 5-6 wildcarded.
func parsePattern(s string) ([]patByte, error) {
	fields := strings.Fields(s)
	if len(fields) < 8 {
		return nil, fmt.Errorf("pattern too short (%d bytes; need >=8 for a specific match)", len(fields))
	}
	out := make([]patByte, 0, len(fields))
	for _, f := range fields {
		if f == "??" || f == "?" {
			out = append(out, patByte{wildcard: true})
			continue
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("bad pattern byte %q: %w", f, err)
		}
		out = append(out, patByte{val: byte(v)})
	}
	return out, nil
}

// loadSignatures reads a signature file. Format:
//
//	{"boringssl": {"read": "55 48 89 e5 ...", "write": "...",
//	               "_offsets": {"read": 222640, "write": 224032}}}
//
// The optional "_offsets" per provider carries the reference-build file offsets,
// enabling inter-function distance validation. A missing file is not an error.
func loadSignatures(path string) ([]signature, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read signatures %s: %w", path, err)
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse signatures %s: %w", path, err)
	}
	var sigs []signature
	for provider, keys := range raw {
		offsets := map[string]uint64{}
		if off, ok := keys["_offsets"]; ok {
			_ = json.Unmarshal(off, &offsets)
		}
		for key, val := range keys {
			if key == "_offsets" {
				continue
			}
			var pat string
			if err := json.Unmarshal(val, &pat); err != nil {
				return nil, fmt.Errorf("signature %s/%s: pattern must be a string", provider, key)
			}
			pb, err := parsePattern(pat)
			if err != nil {
				return nil, fmt.Errorf("signature %s/%s: %w", provider, key, err)
			}
			sigs = append(sigs, signature{
				provider: strings.ToLower(provider), key: key, pattern: pb, refOff: offsets[key],
			})
		}
	}
	return sigs, nil
}

// ExtractSignatures reads prologue byte signatures for the SSL boundary
// functions from a REFERENCE build that retains symbols (e.g. Bun's public
// "profile" build for the exact version a stripped agent bundles). The patterns
// plus reference offsets go into signatures.json; T5 then locates the same
// functions in the stripped build by matching the prologue and verifying that
// the inter-function distances match the reference. This is the technique the
// AgentSight/eunomia writeup uses to recover Claude Code's stripped BoringSSL.
func ExtractSignatures(path string, sigLen int) (provider string, patterns map[string]string, offsets map[string]uint64, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", nil, nil, err
	}
	defer func() { _ = f.Close() }()

	provider = providerFor("", readVersion(f))
	// SSL boundary (libssl/BoringSSL). Merge dynamic + static symbol tables.
	offs := symbolOffsets(f, f.DynamicSymbols)
	for k, v := range symbolOffsets(f, f.Symbols) {
		if _, ok := offs[k]; !ok {
			offs[k] = v
		}
	}
	if len(offs) > 0 {
		if provider == "" {
			provider = "openssl"
		}
	} else if offs = aeadSymbolOffsets(f); len(offs) > 0 {
		// No SSL boundary: EVP_AEAD_CTX_* wrappers (aws-lc-rs/rustls).
		if provider == "" {
			provider = "aws-lc"
		}
	} else {
		// Fall back to the CRYPTOGAMS AEAD assembly (byte-stable, the Codex path).
		offs = symbolOffsetsBySuffix(f, f.DynamicSymbols, asmSymbols)
		for k, v := range symbolOffsetsBySuffix(f, f.Symbols, asmSymbols) {
			if _, ok := offs[k]; !ok {
				offs[k] = v
			}
		}
		if len(offs) == 0 {
			return "", nil, nil, fmt.Errorf("no SSL/AEAD/AEAD-asm symbols in %s (need a symboled reference build)", path)
		}
		provider = providerAEADAsm
	}
	text := f.Section(".text")
	if text == nil {
		return "", nil, nil, fmt.Errorf("no .text section in %s", path)
	}
	tdata, err := text.Data()
	if err != nil {
		return "", nil, nil, err
	}
	patterns = map[string]string{}
	offsets = map[string]uint64{}
	for key, fileOff := range offs {
		idx := int(fileOff - text.Offset)
		if idx < 0 || idx+sigLen > len(tdata) {
			continue
		}
		// Decode with 15 bytes of headroom (max x86 instruction length) so the
		// instruction straddling the sigLen boundary decodes fully and its operand
		// bytes get masked; then keep only the first sigLen pattern bytes.
		hi := idx + sigLen + 15
		if hi > len(tdata) {
			hi = len(tdata)
		}
		pb := wildcardVolatile(tdata[idx:hi])
		patterns[key] = patternString(pb[:sigLen])
		offsets[key] = fileOff
	}
	if len(patterns) == 0 {
		return "", nil, nil, fmt.Errorf("could not read prologues (offsets outside .text)")
	}
	return provider, patterns, offsets, nil
}

// patternString renders a wildcard-aware pattern: fixed bytes as hex, wildcards
// as "??".
func patternString(pb []patByte) string {
	parts := make([]string, len(pb))
	for i, x := range pb {
		if x.wildcard {
			parts[i] = "??"
		} else {
			parts[i] = fmt.Sprintf("%02x", x.val)
		}
	}
	return strings.Join(parts, " ")
}

// wildcardVolatile masks operand bytes that vary between builds of the same
// source (relative displacements, >=2-byte immediates) so a signature from one
// version matches the next; opcode/ModRM/SIB and 1-byte immediates (stable
// discriminators) stay fixed. A byte counts as operand data if flipping it leaves
// the opcode and length unchanged. solveByDistance still pins the final offset,
// so generous masking is safe.
func wildcardVolatile(code []byte) []patByte {
	out := make([]patByte, len(code))
	for i := range code {
		out[i] = patByte{val: code[i]}
	}
	pos := 0
	for pos < len(code) {
		inst, err := x86asm.Decode(code[pos:], 64)
		if err != nil || inst.Len == 0 {
			pos++
			continue
		}
		end := pos + inst.Len
		if end > len(code) {
			break
		}
		// Exact PC-relative operand bytes.
		for k := 0; k < inst.PCRel; k++ {
			if p := pos + inst.PCRelOff + k; p < end {
				out[p] = patByte{wildcard: true}
			}
		}
		// Differential: byte is operand data if perturbing it preserves Op+Len.
		vol := make([]bool, inst.Len)
		for b := 1; b < inst.Len; b++ {
			vol[b] = isOperandByte(code[pos:end], b, inst.Op, inst.Len)
		}
		// Mask only runs of length >=2 (keeps 1-byte imm8 discriminators fixed).
		for b := 1; b < inst.Len; {
			if !vol[b] {
				b++
				continue
			}
			j := b
			for j < inst.Len && vol[j] {
				j++
			}
			if j-b >= 2 {
				for k := b; k < j; k++ {
					out[pos+k] = patByte{wildcard: true}
				}
			}
			b = j
		}
		pos = end
	}
	return out
}

// isOperandByte reports whether byte idx of a decoded instruction is operand data
// (immediate/displacement) rather than opcode/ModRM/SIB: flipping it must leave
// the opcode and instruction length unchanged for several perturbations.
func isOperandByte(inst []byte, idx int, op x86asm.Op, length int) bool {
	tmp := make([]byte, len(inst))
	for _, delta := range []byte{0xff, 0x01, 0x80} {
		copy(tmp, inst)
		tmp[idx] ^= delta
		d, err := x86asm.Decode(tmp, 64)
		if err != nil || d.Op != op || d.Len != length {
			return false
		}
	}
	return true
}

// providerFor maps a version banner / library label to a signature provider key.
func providerFor(library, version string) string {
	s := strings.ToLower(library + " " + version)
	switch {
	case strings.Contains(s, "boringssl"):
		return "boringssl"
	case strings.Contains(s, "aws-lc"):
		return "aws-lc"
	case strings.Contains(s, "openssl"):
		return "openssl"
	}
	return ""
}

// resolvePatternMatchWith scans f's executable section for the provider's
// signatures and returns the recovered file offsets. Exposed for testing.
func resolvePatternMatchWith(f *elf.File, sigs []signature, provider string) (map[string]uint64, bool) {
	if provider == "" || len(sigs) == 0 {
		return nil, false
	}
	// Skip the (expensive) .text read unless a signature actually targets this
	// provider — the ladder probes several providers per binary.
	hasProvider := false
	for _, sig := range sigs {
		if sig.provider == provider {
			hasProvider = true
			break
		}
	}
	if !hasProvider {
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
	cands := map[string][]uint64{} // key -> all candidate file offsets
	refs := map[string]uint64{}
	for _, sig := range sigs {
		if sig.provider != provider {
			continue
		}
		for _, i := range scanAll(data, sig.pattern) {
			cands[sig.key] = append(cands[sig.key], text.Offset+uint64(i))
		}
		refs[sig.key] = sig.refOff
	}
	if len(cands) == 0 {
		return nil, false
	}
	return solveByDistance(cands, refs)
}

// scanAll returns every index at which pattern matches data. It anchors on the
// pattern's longest run of fixed (non-wildcard) bytes and uses bytes.Index (SIMD-
// accelerated) to find candidate positions, verifying the full pattern only
// there. This is decisive on large binaries: a naive O(n*m) scan of a stripped
// agent's multi-hundred-MB .text takes seconds, losing the uprobe-attach race
// against short-lived agent invocations.
func scanAll(data []byte, pattern []patByte) []int {
	n, m := len(data), len(pattern)
	if m == 0 || n < m {
		return nil
	}
	anchor, anchorOff := longestFixedRun(pattern)
	if len(anchor) == 0 {
		return scanAllNaive(data, pattern) // all-wildcard pattern: no anchor
	}
	var out []int
	// Search successive windows for the anchor, then verify the whole pattern at
	// the implied start offset.
	for base := 0; ; {
		rel := bytes.Index(data[base:], anchor)
		if rel < 0 {
			break
		}
		hit := base + rel
		start := hit - anchorOff
		if start >= 0 && start+m <= n && matchAt(data, pattern, start) {
			out = append(out, start)
		}
		base = hit + 1
	}
	return out
}

// longestFixedRun returns the longest contiguous run of non-wildcard bytes in the
// pattern and its start offset within the pattern.
func longestFixedRun(pattern []patByte) ([]byte, int) {
	bestStart, bestLen := 0, 0
	curStart, curLen := 0, 0
	for i, pb := range pattern {
		if pb.wildcard {
			curLen = 0
			curStart = i + 1
			continue
		}
		if curLen == 0 {
			curStart = i
		}
		curLen++
		if curLen > bestLen {
			bestStart, bestLen = curStart, curLen
		}
	}
	if bestLen == 0 {
		return nil, 0
	}
	run := make([]byte, bestLen)
	for i := 0; i < bestLen; i++ {
		run[i] = pattern[bestStart+i].val
	}
	return run, bestStart
}

// matchAt reports whether pattern matches data at index start (caller ensures
// start+len(pattern) <= len(data)).
func matchAt(data []byte, pattern []patByte, start int) bool {
	for j := range pattern {
		if !pattern[j].wildcard && data[start+j] != pattern[j].val {
			return false
		}
	}
	return true
}

// scanAllNaive is the O(n*m) fallback for all-wildcard patterns.
func scanAllNaive(data []byte, pattern []patByte) []int {
	n, m := len(data), len(pattern)
	var out []int
	for i := 0; i+m <= n; i++ {
		if matchAt(data, pattern, i) {
			out = append(out, i)
		}
	}
	return out
}

// solveByDistance pins each function's offset using the reference inter-function
// distances: thin wrappers (SSL_read/SSL_write) share an identical prologue, so a
// pattern alone is ambiguous but the reference deltas fix the assignment.
//
// Distances are only LOCALLY stable across versions (adjacent wrappers keep their
// spacing; a resized intervening function shifts more-distant pairs), so this
// pins each uniquely-matched key directly, then resolves each ambiguous key
// against its NEAREST pinned reference neighbour, iterating so a freshly pinned
// key can anchor others. Falls back to a single-anchor solve when nothing
// matches uniquely.
func solveByDistance(cands map[string][]uint64, refs map[string]uint64) (map[string]uint64, bool) {
	hasRefs := false
	for _, r := range refs {
		if r != 0 {
			hasRefs = true
			break
		}
	}
	if !hasRefs {
		out := map[string]uint64{}
		for k, c := range cands {
			if len(c) == 1 {
				out[k] = c[0]
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	}

	out := map[string]uint64{}
	// Pin keys with a single candidate: a unique prologue match is self-anchoring.
	for k, c := range cands {
		if len(c) == 1 {
			out[k] = c[0]
		}
	}
	// Resolve ambiguous keys via the nearest already-pinned reference neighbour.
	for progress := true; progress; {
		progress = false
		for k, c := range cands {
			if _, done := out[k]; done || refs[k] == 0 {
				continue
			}
			best := ""
			for p := range out {
				if refs[p] == 0 {
					continue
				}
				if best == "" || absI64(int64(refs[k])-int64(refs[p])) < absI64(int64(refs[k])-int64(refs[best])) {
					best = p
				}
			}
			if best == "" {
				continue
			}
			want := int64(out[best]) + (int64(refs[k]) - int64(refs[best]))
			var match int64 = -1
			count := 0
			for _, cc := range c {
				if int64(cc) == want {
					match = int64(cc)
					count++
				}
			}
			if count == 1 {
				out[k] = uint64(match)
				progress = true
			}
		}
	}
	if len(out) >= 2 {
		return out, true
	}

	// Fallback: single-anchor solve (all keys ambiguous, no unique match).
	anchor := ""
	for k := range cands {
		if refs[k] == 0 || len(cands[k]) == 0 {
			continue
		}
		if anchor == "" || len(cands[k]) < len(cands[anchor]) {
			anchor = k
		}
	}
	if anchor == "" {
		return nil, false
	}
	var solutions []map[string]uint64
	for _, av := range cands[anchor] {
		sol := map[string]uint64{anchor: av}
		ok := true
		for k, r := range refs {
			if k == anchor || r == 0 {
				continue
			}
			want := int64(av) + (int64(r) - int64(refs[anchor]))
			found := false
			for _, c := range cands[k] {
				if int64(c) == want {
					sol[k] = c
					found = true
					break
				}
			}
			if !found {
				ok = false
				break
			}
		}
		if ok && len(sol) >= 2 {
			solutions = append(solutions, sol)
		}
	}
	if len(solutions) != 1 {
		return nil, false
	}
	return solutions[0], true
}

func absI64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
