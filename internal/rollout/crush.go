// SPDX-License-Identifier: Apache-2.0

// Crush session-store reader. Unlike the JSONL agents, Crush (a Go agent)
// records its conversation in a per-project SQLite database at
// <cwd>/.crush/crush.db, which this reader polls and correlates to the session
// on the timeline.
package rollout

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (CGO-free)

	"github.com/boanlab/agentknox/pkg/types"
)

// crushWalkDepth bounds the per-home directory walk that discovers .crush/crush.db.
const crushWalkDepth = 7

// CrushReader polls Crush's per-project SQLite stores for newly-inserted messages.
type CrushReader struct {
	log     *zap.Logger
	lastRow map[string]int64 // db path -> last message rowid emitted
}

// NewCrushReader constructs a CrushReader.
func NewCrushReader(log *zap.Logger) *CrushReader {
	if log == nil {
		log = zap.NewNop()
	}
	return &CrushReader{log: log, lastRow: make(map[string]int64)}
}

// CrushDBs discovers .crush/crush.db files under the users' homes (bounded depth).
func CrushDBs() []string {
	roots := []string{"/root"}
	if h, err := os.UserHomeDir(); err == nil {
		roots = append(roots, h)
	}
	if es, err := os.ReadDir("/home"); err == nil {
		for _, e := range es {
			if e.IsDir() {
				roots = append(roots, filepath.Join("/home", e.Name()))
			}
		}
	}
	seen := make(map[string]bool)
	var dbs []string
	for _, root := range roots {
		if seen[root] {
			continue
		}
		seen[root] = true
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && strings.Count(p[len(root):], string(os.PathSeparator)) > crushWalkDepth {
				return filepath.SkipDir
			}
			if !d.IsDir() && d.Name() == "crush.db" && filepath.Base(filepath.Dir(p)) == ".crush" {
				dbs = append(dbs, p)
			}
			return nil
		})
	}
	return dbs
}

// Watch discovers and polls Crush databases until ctx is cancelled, invoking
// onItems for each batch of newly-inserted messages. Pre-existing rows are
// skipped so old sessions are not replayed.
func (r *CrushReader) Watch(ctx context.Context, onItems func(file string, items []Item)) {
	known := CrushDBs()
	r.log.Debug("crush reader started", zap.Strings("dbs", known))
	for _, db := range known {
		r.seed(db)
	}
	poll := time.NewTicker(400 * time.Millisecond)
	discover := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	defer discover.Stop()
	inKnown := func(db string) bool {
		for _, k := range known {
			if k == db {
				return true
			}
		}
		return false
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-discover.C:
			for _, db := range CrushDBs() {
				if !inKnown(db) {
					known = append(known, db) // new db: lastRow defaults to 0, read from start
					r.log.Debug("crush db discovered", zap.String("db", db))
				}
			}
		case <-poll.C:
			for _, db := range known {
				r.poll(db, onItems)
			}
		}
	}
}

// seed records the current max rowid so a database present at start is not replayed.
func (r *CrushReader) seed(db string) {
	if row, ok := r.maxRowID(db); ok {
		r.lastRow[db] = row
	}
}

// maxRowID returns the highest message rowid in db.
func (r *CrushReader) maxRowID(db string) (int64, bool) {
	conn, cleanup, err := openCrushDB(db)
	if err != nil {
		return 0, false
	}
	defer cleanup()
	defer conn.Close()
	var max int64
	if err := conn.QueryRow("SELECT COALESCE(MAX(rowid),0) FROM messages").Scan(&max); err != nil {
		return 0, false
	}
	return max, true
}

// poll reads messages appended since the last rowid and emits their items.
func (r *CrushReader) poll(db string, onItems func(file string, items []Item)) {
	conn, cleanup, err := openCrushDB(db)
	if err != nil {
		return
	}
	defer cleanup()
	defer conn.Close()
	rows, err := conn.Query(
		"SELECT rowid, role, parts, created_at FROM messages WHERE rowid > ? ORDER BY rowid",
		r.lastRow[db])
	if err != nil {
		return
	}
	defer rows.Close()
	max := r.lastRow[db]
	var items []Item
	for rows.Next() {
		var rid, created int64
		var role, parts string
		if err := rows.Scan(&rid, &role, &parts, &created); err != nil {
			continue
		}
		if rid > max {
			max = rid
		}
		items = append(items, parseCrushParts(role, parts, time.Unix(created, 0))...)
	}
	if max != r.lastRow[db] || len(items) > 0 {
		r.log.Debug("crush poll", zap.String("db", db),
			zap.Int64("from_rowid", r.lastRow[db]), zap.Int64("to_rowid", max), zap.Int("items", len(items)))
	}
	r.lastRow[db] = max
	if len(items) > 0 && onItems != nil {
		onItems(db, items)
	}
}

// openCrushDB copies Crush's live SQLite store to a private, root-owned temp file
// and opens the copy, so the daemon never creates or modifies files next to the
// agent's DB. The pure-Go modernc.org/sqlite driver ignores the immutable/mode=ro
// URI flags and opens the DSN read-write, which would recreate a deleted crush.db
// or add a root-owned -shm/-wal to a live one and lock Crush out of its own store;
// reading a disposable copy avoids that. The caller must invoke the returned
// cleanup. An uncheckpointed WAL is copied alongside so its rows are recovered on
// open (best-effort: Crush's live intent is captured at its Go crypto/tls boundary).
func openCrushDB(db string) (*sql.DB, func(), error) {
	noop := func() {}
	if _, err := os.Stat(db); err != nil {
		return nil, noop, err // not present yet; never (re)create the agent's DB
	}
	dir, err := os.MkdirTemp("", "ak-crush")
	if err != nil {
		return nil, noop, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	dst := filepath.Join(dir, "crush.db")
	if err := copyFile(db, dst); err != nil {
		cleanup()
		return nil, noop, err
	}
	if _, err := os.Stat(db + "-wal"); err == nil {
		_ = copyFile(db+"-wal", dst+"-wal") // committed-but-uncheckpointed rows
	}
	conn, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(200)", dst))
	if err != nil {
		cleanup()
		return nil, noop, err
	}
	return conn, cleanup, nil
}

// copyFile writes a private (0600) copy of src at dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	return cerr
}

// crushPart is one element of a Crush message's parts array: {type, data}.
type crushPart struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// parseCrushParts parses a message row (role + parts JSON) into semantic items.
func parseCrushParts(role, partsJSON string, ts time.Time) []Item {
	var parts []crushPart
	if json.Unmarshal([]byte(partsJSON), &parts) != nil {
		return nil
	}
	var items []Item
	for _, p := range parts {
		switch p.Type {
		case "text":
			var d struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(p.Data, &d)
			if strings.TrimSpace(d.Text) == "" {
				continue
			}
			kind := types.SemAssistant
			if role == "user" {
				kind = types.SemPrompt
			}
			items = append(items, Item{Time: ts, Kind: kind, Text: d.Text})
		case "tool_call":
			var d struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Input string `json:"input"` // Crush serializes tool input as a JSON string
			}
			_ = json.Unmarshal(p.Data, &d)
			var input map[string]any
			_ = json.Unmarshal([]byte(d.Input), &input)
			items = append(items, Item{Time: ts, Kind: types.SemToolUse, ToolUse: &types.ToolUse{
				ID:          d.ID,
				Name:        d.Name,
				Input:       input,
				IntentClass: classifyCrushIntent(d.Name),
			}})
		case "tool_result":
			var d struct {
				ToolCallID string `json:"tool_call_id"`
				Content    string `json:"content"`
			}
			_ = json.Unmarshal(p.Data, &d)
			items = append(items, Item{Time: ts, Kind: types.SemToolResult,
				ToolResult: &types.ToolUse{ID: d.ToolCallID}, Text: d.Content})
		}
	}
	return items
}

// classifyCrushIntent maps a Crush tool name to a coarse intent class.
func classifyCrushIntent(name string) string {
	switch name {
	case "bash":
		return "exec"
	case "view", "ls", "grep", "glob":
		return "read"
	case "write", "edit", "multiedit":
		return "write"
	case "fetch", "sourcegraph", "download":
		return "network"
	}
	return ""
}
