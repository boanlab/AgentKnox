// SPDX-License-Identifier: Apache-2.0

package rollout

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Tailer watches a transcript directory and streams newly-appended transcript
// items to a callback. It polls (robust across the dated subdirectory tree Codex
// creates) and reads only bytes appended after it started, so old sessions are
// not replayed while live ones are captured from the point monitoring began.
type Tailer struct {
	dir     string
	log     *zap.Logger
	offsets map[string]int64
	match   func(name string) bool
	parse   func(line []byte) []Item
}

// SessionsDir returns $CODEX_HOME/sessions ($CODEX_HOME defaults to ~/.codex),
// or "" if no home is resolvable.
func SessionsDir() string {
	base := os.Getenv("CODEX_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".codex")
	}
	return filepath.Join(base, "sessions")
}

// NewTailer constructs a Tailer for the Codex rollout format (dir typically
// SessionsDir()).
func NewTailer(dir string, log *zap.Logger) *Tailer {
	return NewTailerWith(dir, log, codexMatch, ParseLine)
}

// NewTailerWith constructs a Tailer with a custom filename predicate and line
// parser, so the same polling/offset machinery serves every vendor's
// transcript format.
func NewTailerWith(dir string, log *zap.Logger, match func(string) bool, parse func([]byte) []Item) *Tailer {
	if log == nil {
		log = zap.NewNop()
	}
	return &Tailer{dir: dir, log: log, offsets: make(map[string]int64), match: match, parse: parse}
}

// codexMatch is the default filename predicate: a rollout-<...>.jsonl transcript.
func codexMatch(name string) bool {
	return strings.HasPrefix(name, "rollout-") && strings.HasSuffix(name, ".jsonl")
}

// Watch polls the sessions tree until ctx is cancelled, invoking onItems with the
// file path and the items parsed from each batch of newly-appended lines.
func (t *Tailer) Watch(ctx context.Context, onItems func(file string, items []Item)) {
	// Seed offsets to current sizes so pre-existing sessions are not replayed.
	t.scan(nil)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.scan(onItems)
		}
	}
}

// scan walks the tree once, emitting items from any bytes appended since the last
// scan. When onItems is nil (the seeding pass) it only records current sizes.
func (t *Tailer) scan(onItems func(file string, items []Item)) {
	_ = filepath.WalkDir(t.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !t.match(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		size := info.Size()
		prev, known := t.offsets[path]
		if !known {
			// First sight. During seeding (onItems==nil) skip existing content;
			// a file that first appears later is a new session, read from the start.
			if onItems == nil {
				t.offsets[path] = size
				return nil
			}
			prev = 0
		}
		if size <= prev {
			t.offsets[path] = size
			return nil
		}
		t.readFrom(path, prev, onItems)
		return nil
	})
}

// readFrom reads appended lines from off and emits their parsed items.
func (t *Tailer) readFrom(path string, off int64, onItems func(file string, items []Item)) {
	f, err := os.Open(path)
	if err != nil {
		t.log.Debug("tailer open failed", zap.String("path", path), zap.Error(err))
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, 0); err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var items []Item
	consumed := off
	for sc.Scan() {
		line := sc.Bytes()
		consumed += int64(len(line)) + 1 // + newline
		items = append(items, t.parse(line)...)
	}
	t.offsets[path] = consumed
	t.log.Debug("tailer read", zap.String("path", path),
		zap.Int64("from", off), zap.Int64("to", consumed), zap.Int("items", len(items)))
	if len(items) > 0 && onItems != nil {
		onItems(path, items)
	}
}
