// SPDX-License-Identifier: Apache-2.0
package archive

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCandidates(t *testing.T) {
	a := New(t.TempDir(), nil)
	sess := "s1"
	a.NoteWrite(sess, "/tmp/agent/run.py", time.Now())
	a.NoteWrite(sess, "/tmp/agent/tool", time.Now())

	tests := []struct {
		name    string
		exe     string
		argv    []string
		wantKey string
	}{
		{"interpreter+written-script", "/usr/bin/python3", []string{"/usr/bin/python3", "/tmp/agent/run.py"}, "/tmp/agent/run.py"},
		{"interpreter+script-by-ext", "/usr/bin/node", []string{"node", "/home/x/app.js"}, "/home/x/app.js"},
		{"written-executable", "/tmp/agent/tool", []string{"/tmp/agent/tool", "--flag"}, "/tmp/agent/tool"},
		{"non-script-flags-ignored", "/usr/bin/python3", []string{"python3", "-c", "print(1)"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := a.candidates(sess, tc.exe, tc.argv)
			if tc.wantKey == "" {
				if len(got) != 0 {
					t.Fatalf("expected no candidates, got %v", got)
				}
				return
			}
			if _, ok := got[tc.wantKey]; !ok {
				t.Fatalf("expected candidate %q, got %v", tc.wantKey, got)
			}
		})
	}
}

func TestArchiveCopyAndDedup(t *testing.T) {
	dir := t.TempDir()
	a := New(dir, nil)

	src := filepath.Join(t.TempDir(), "script.py")
	if err := os.WriteFile(src, []byte("print('hello from agent')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a.archive("sess1", 4242, src, "interpreter-script", []string{"python3", src})

	// A copy + a .meta.json must appear under dir/sess1/.
	entries, _ := os.ReadDir(filepath.Join(dir, "sess1"))
	var copies, metas int
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			metas++
		} else {
			copies++
		}
	}
	if copies != 1 || metas != 1 {
		t.Fatalf("want 1 copy + 1 meta, got copies=%d metas=%d", copies, metas)
	}

	// Dedup: same content archived again must not add another copy.
	a.archive("sess1", 4243, src, "interpreter-script", []string{"python3", src})
	entries2, _ := os.ReadDir(filepath.Join(dir, "sess1"))
	if len(entries2) != len(entries) {
		t.Fatalf("dedup failed: entries grew from %d to %d", len(entries), len(entries2))
	}
}
