// SPDX-License-Identifier: Apache-2.0
// Package archive preserves scripts and code that an agent writes and then runs.
// When a session writes a file (e.g. a Python/JS/shell script) and later executes
// it — directly or via an interpreter — the file content at execution time is
// copied into a per-session archive with metadata, for forensics and audit.
package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// maxArchiveBytes bounds the size of a single archived file.
const maxArchiveBytes = 5 << 20 // 5 MiB

var interpreters = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "bun": true, "deno": true, "ts-node": true,
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"ruby": true, "perl": true, "php": true, "Rscript": true,
}

var scriptExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".mjs": true, ".cjs": true,
	".sh": true, ".bash": true, ".rb": true, ".pl": true, ".php": true,
	".r": true, ".lua": true,
}

// Archiver copies session-written scripts on execution.
type Archiver struct {
	dir string
	log *zap.Logger

	mu      sync.Mutex
	written map[string]map[string]time.Time // sessionID -> path -> first write time
	seen    map[string]struct{}             // content sha256 already archived
}

// New creates an Archiver rooted at dir (created on demand).
func New(dir string, log *zap.Logger) *Archiver {
	if log == nil {
		log = zap.NewNop()
	}
	return &Archiver{
		dir:     dir,
		log:     log,
		written: make(map[string]map[string]time.Time),
		seen:    make(map[string]struct{}),
	}
}

// NoteWrite records that a session wrote to a path (from a file write/create event).
func (a *Archiver) NoteWrite(sessionID, path string, t time.Time) {
	if sessionID == "" || path == "" || !filepath.IsAbs(path) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.written[sessionID]
	if m == nil {
		m = make(map[string]time.Time)
		a.written[sessionID] = m
	}
	if _, ok := m[path]; !ok {
		m[path] = t
	}
}

// OnExec inspects an exec by a session and archives the executed script/code.
// hostPID is the executing process; exePath is the program from the exec event.
// It reads /proc/<pid>/cmdline to recover the script argument for interpreters.
func (a *Archiver) OnExec(sessionID string, hostPID int32, exePath string) {
	if sessionID == "" {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			a.log.Warn("archive: recovered from panic in OnExec", zap.Any("panic", r))
		}
	}()
	argv := readCmdline(hostPID)
	for path, reason := range a.candidates(sessionID, exePath, argv) {
		a.archive(sessionID, hostPID, path, reason, argv)
	}
}

// candidates selects the script/code files to archive for an exec. It flags the
// executed program if the session wrote it, and the script argument of an
// interpreter (by extension or because the session wrote it).
func (a *Archiver) candidates(sessionID, exePath string, argv []string) map[string]string {
	out := map[string]string{}
	add := func(p, reason string) {
		if p != "" && filepath.IsAbs(p) {
			out[p] = reason
		}
	}
	if a.wroteFile(sessionID, exePath) {
		add(exePath, "agent-written-executable")
	}
	prog := exePath
	if len(argv) > 0 {
		prog = argv[0]
	}
	if interpreters[filepath.Base(prog)] && len(argv) > 1 {
		for _, arg := range argv[1:] {
			if strings.HasPrefix(arg, "-") {
				continue // flag, not a script path
			}
			if scriptExts[strings.ToLower(filepath.Ext(arg))] || a.wroteFile(sessionID, arg) {
				add(arg, "interpreter-script")
				break
			}
		}
	}
	for _, arg := range argv {
		if a.wroteFile(sessionID, arg) {
			add(arg, "agent-written-arg")
		}
	}
	return out
}

func (a *Archiver) wroteFile(sessionID, path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.written[sessionID]
	if m == nil {
		return false
	}
	_, ok := m[path]
	return ok
}

func (a *Archiver) archive(sessionID string, pid int32, path, reason string, argv []string) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxArchiveBytes {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	sum := sha256.Sum256(content)
	hexsum := hex.EncodeToString(sum[:])

	a.mu.Lock()
	if _, dup := a.seen[hexsum]; dup {
		a.mu.Unlock()
		return
	}
	a.seen[hexsum] = struct{}{}
	a.mu.Unlock()

	destDir := filepath.Join(a.dir, sessionID)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		a.log.Warn("archive: mkdir", zap.Error(err))
		return
	}
	stamp := fi.ModTime().UTC().Format("20060102T150405")
	base := fmt.Sprintf("%s_%s_%s", stamp, hexsum[:12], filepath.Base(path))
	if err := os.WriteFile(filepath.Join(destDir, base), content, 0o600); err != nil {
		a.log.Warn("archive: write copy", zap.Error(err))
		return
	}
	meta := map[string]any{
		"session_id": sessionID, "pid": pid, "path": path,
		"reason": reason, "argv": argv, "sha256": hexsum,
		"size": fi.Size(), "archived_at": time.Now().UTC().Format(time.RFC3339),
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(filepath.Join(destDir, base+".meta.json"), mb, 0o600)

	a.log.Info("archive: preserved agent script",
		zap.String("session", sessionID), zap.String("path", path),
		zap.String("reason", reason), zap.String("sha256", hexsum[:12]))
}

// SessionEnded drops per-session write tracking to bound memory.
func (a *Archiver) SessionEnded(sessionID string) {
	a.mu.Lock()
	delete(a.written, sessionID)
	a.mu.Unlock()
}

func readCmdline(pid int32) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
