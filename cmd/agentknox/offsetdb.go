// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/boanlab/agentknox/internal/resolver"
)

// runOffsetDB is the `agentknox offsetdb` subcommand: it builds/merges the
// build-id → offset cache (T4) that lets the resolver attach semantic uprobes on
// stripped binaries. Three input modes:
//
//	--binary PATH   extract SSL/AEAD offsets from PATH's symbols (a symboled lib)
//	--pid N         extract from the TLS library a running process has loaded
//	--set SPEC      add a manual entry (offsets recovered offline via RE/Ghidra):
//	                "<buildid>:read=0x..,write=0x..[,handshake=..,aead_open=..,aead_seal=..]"
//
// The result is written to --out (a JSON object keyed by build-id), merging with
// any existing file, and mirrored to stdout.
func runOffsetDB(args []string) error {
	fs := flag.NewFlagSet("offsetdb", flag.ContinueOnError)
	binary := fs.String("binary", "", "binary/library to extract offsets from (by symbol)")
	pid := fs.Int("pid", 0, "extract from the TLS library loaded by this running pid")
	set := fs.String("set", "", "manual entry: <buildid>:read=0x..,write=0x..")
	out := fs.String("out", "", "offset DB JSON to write/merge (default: stdout only)")
	signatures := fs.Bool("signatures", false, "emit a T5 signatures.json (prologue patterns) from --binary instead of an offset DB")
	sigLen := fs.Int("siglen", 24, "signature prologue length in bytes (with --signatures)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// --signatures: extract prologue patterns from a symboled reference build so
	// T5 can locate the same functions in a stripped build of the same code.
	if *signatures {
		if *binary == "" {
			return fmt.Errorf("--signatures requires --binary <symboled reference build>")
		}
		return runSignatures(*binary, *sigLen, *out)
	}

	db := map[string]map[string]uint64{}
	if *out != "" {
		if data, err := os.ReadFile(*out); err == nil {
			_ = json.Unmarshal(data, &db) // best-effort merge with existing
		}
	}

	var buildID string
	var offs map[string]uint64
	switch {
	case *set != "":
		id, o, err := parseManualSet(*set)
		if err != nil {
			return err
		}
		buildID, offs = id, o
	case *pid != 0:
		lib, ok := resolver.FindProcessTLSLib(int32(*pid))
		if !ok {
			return fmt.Errorf("no TLS library found in /proc/%d/maps", *pid)
		}
		fmt.Fprintf(os.Stderr, "offsetdb: pid %d uses %s\n", *pid, lib)
		id, o, err := resolver.ExtractOffsets(lib)
		if err != nil {
			return err
		}
		buildID, offs = id, o
	case *binary != "":
		id, o, err := resolver.ExtractOffsets(*binary)
		if err != nil {
			return err
		}
		buildID, offs = id, o
	default:
		return fmt.Errorf("one of --binary, --pid, or --set is required")
	}

	if buildID == "" {
		return fmt.Errorf("no build-id (a .note.gnu.build-id is required to key the entry)")
	}
	if len(offs) == 0 {
		return fmt.Errorf("no offsets recovered — the binary is stripped; recover them offline (Ghidra/IDA) and add with --set")
	}

	// Merge (new offsets win for the same key).
	entry := db[buildID]
	if entry == nil {
		entry = map[string]uint64{}
	}
	for k, v := range offs {
		entry[k] = v
	}
	db[buildID] = entry

	pretty, _ := json.MarshalIndent(db, "", "  ")
	fmt.Printf("%s\n", pretty)
	fmt.Fprintf(os.Stderr, "offsetdb: build-id %s → %s\n", buildID, keyList(offs))
	if *out != "" {
		if err := os.WriteFile(*out, append(pretty, '\n'), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", *out, err)
		}
		fmt.Fprintf(os.Stderr, "offsetdb: wrote %s\n", *out)
	}
	return nil
}

// runSignatures extracts prologue signatures from a symboled reference build and
// writes/merges them into a signatures.json (the T5 input).
func runSignatures(binary string, sigLen int, out string) error {
	provider, patterns, offsets, err := resolver.ExtractSignatures(binary, sigLen)
	if err != nil {
		return err
	}
	// Load-merge existing file.
	db := map[string]map[string]any{}
	if out != "" {
		if data, err := os.ReadFile(out); err == nil {
			_ = json.Unmarshal(data, &db)
		}
	}
	entry := db[provider]
	if entry == nil {
		entry = map[string]any{}
	}
	for k, p := range patterns {
		entry[k] = p
	}
	entry["_offsets"] = offsets
	db[provider] = entry

	pretty, _ := json.MarshalIndent(db, "", "  ")
	fmt.Printf("%s\n", pretty)
	fmt.Fprintf(os.Stderr, "offsetdb: provider %s → signatures for %s (%d-byte prologues)\n", provider, keyListAny(patterns), sigLen)
	if out != "" {
		if err := os.WriteFile(out, append(pretty, '\n'), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		fmt.Fprintf(os.Stderr, "offsetdb: wrote %s\n", out)
	}
	return nil
}

func keyListAny(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// parseManualSet parses "<buildid>:key=0x..,key=0x..".
func parseManualSet(s string) (string, map[string]uint64, error) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", nil, fmt.Errorf("--set must be <buildid>:key=val,...")
	}
	buildID := strings.TrimSpace(s[:i])
	valid := map[string]bool{"read": true, "write": true, "handshake": true, "aead_open": true, "aead_seal": true}
	offs := map[string]uint64{}
	for _, kv := range strings.Split(s[i+1:], ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return "", nil, fmt.Errorf("bad key=val %q", kv)
		}
		key := strings.TrimSpace(kv[:eq])
		if !valid[key] {
			return "", nil, fmt.Errorf("unknown offset key %q (want read|write|handshake|aead_open|aead_seal)", key)
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(kv[eq+1:]), "0x"), 16, 64)
		if err != nil {
			return "", nil, fmt.Errorf("bad hex offset for %q: %w", key, err)
		}
		offs[key] = v
	}
	return buildID, offs, nil
}

func keyList(m map[string]uint64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
