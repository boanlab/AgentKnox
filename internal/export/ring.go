// SPDX-License-Identifier: Apache-2.0

package export

// ring is a fixed-capacity circular buffer of Envelopes retaining the most
// recent items for replay via the Recent RPC. It is not safe for concurrent
// use; the Server guards it with s.mu.
type ring struct {
	buf   []Envelope
	next  int // index to write next
	count int // number of valid entries (<= cap)
}

func newRing(capacity int) *ring {
	if capacity < 1 {
		capacity = 1
	}
	return &ring{buf: make([]Envelope, capacity)}
}

// push appends env, overwriting the oldest entry when full.
func (r *ring) push(env Envelope) {
	r.buf[r.next] = env
	r.next = (r.next + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
}

// snapshot returns up to limit most-recent entries in chronological order
// (oldest first, newest last). limit <= 0 returns all retained entries.
func (r *ring) snapshot(limit int) []Envelope {
	if r.count == 0 {
		return nil
	}
	n := r.count
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Envelope, 0, n)
	// Oldest valid index of the full window.
	start := (r.next - r.count + len(r.buf)) % len(r.buf)
	// Advance start so we only emit the last n entries.
	start = (start + (r.count - n) + len(r.buf)) % len(r.buf)
	for i := 0; i < n; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}
	return out
}
