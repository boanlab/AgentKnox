// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	// walRotateBytes is the approximate size at which a WAL segment is rotated.
	walRotateBytes = 32 << 20 // ~32 MiB
	// walMaxSegments is how many rotated segments are retained on disk.
	walMaxSegments = 8
)

// wal is an append-only JSONL segment writer. Each line is one marshaled
// Envelope. Segments are named wal-<seq>.jsonl and rotate at ~walRotateBytes;
// only the newest walMaxSegments are retained (durable audit trail).
type wal struct {
	dir string
	log *zap.Logger

	mu      sync.Mutex
	seq     uint64
	f       *os.File
	w       *bufio.Writer
	written int64
}

// newWAL prepares walDir and opens (or resumes) a segment. The next sequence
// number is derived from any existing wal-*.jsonl files so restarts do not
// overwrite prior segments.
func newWAL(dir string, log *zap.Logger) (*wal, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("export: create wal dir: %w", err)
	}
	w := &wal{dir: dir, log: log}
	w.seq = w.maxExistingSeq() + 1
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

// maxExistingSeq scans the directory for the highest wal-<seq>.jsonl sequence.
func (w *wal) maxExistingSeq() uint64 {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0
	}
	var max uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n, ok := parseSegSeq(e.Name()); ok && n > max {
			max = n
		}
	}
	return max
}

func parseSegSeq(name string) (uint64, bool) {
	if !strings.HasPrefix(name, "wal-") || !strings.HasSuffix(name, ".jsonl") {
		return 0, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(name, "wal-"), ".jsonl")
	n, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (w *wal) segPath(seq uint64) string {
	return filepath.Join(w.dir, fmt.Sprintf("wal-%d.jsonl", seq))
}

// openLocked opens the current segment for append. Caller holds w.mu.
func (w *wal) openLocked() error {
	f, err := os.OpenFile(w.segPath(w.seq), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("export: open wal segment: %w", err)
	}
	if info, err := f.Stat(); err == nil {
		w.written = info.Size()
	} else {
		w.written = 0
	}
	w.f = f
	w.w = bufio.NewWriter(f)
	return nil
}

// append marshals env to a single JSONL line, rotating the segment first if it
// has grown past the rotation threshold.
func (w *wal) append(env Envelope) error {
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.written >= walRotateBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.w.Write(line)
	if err != nil {
		return err
	}
	if err := w.w.WriteByte('\n'); err != nil {
		return err
	}
	w.written += int64(n) + 1
	return nil
}

// rotateLocked flushes and closes the current segment, opens the next one, and
// prunes old segments. Caller holds w.mu.
func (w *wal) rotateLocked() error {
	if w.w != nil {
		_ = w.w.Flush()
	}
	if w.f != nil {
		_ = w.f.Close()
	}
	w.seq++
	if err := w.openLocked(); err != nil {
		return err
	}
	w.pruneLocked()
	return nil
}

// pruneLocked deletes all but the newest walMaxSegments segments.
func (w *wal) pruneLocked() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	var seqs []uint64
	for _, e := range entries {
		if n, ok := parseSegSeq(e.Name()); ok {
			seqs = append(seqs, n)
		}
	}
	if len(seqs) <= walMaxSegments {
		return
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, n := range seqs[:len(seqs)-walMaxSegments] {
		if err := os.Remove(w.segPath(n)); err != nil && w.log != nil {
			w.log.Warn("export: prune wal segment", zap.Uint64("seq", n), zap.Error(err))
		}
	}
}

// close flushes and closes the current segment.
func (w *wal) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	if w.w != nil {
		err = w.w.Flush()
	}
	if w.f != nil {
		if cerr := w.f.Close(); cerr != nil && err == nil {
			err = cerr
		}
		w.f = nil
	}
	return err
}
