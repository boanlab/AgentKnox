// SPDX-License-Identifier: Apache-2.0
package types

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
)

// Event IDs must be unique within a daemon run (for correlation/dedup), not
// globally unique or cryptographically random. A per-process random prefix plus
// a monotonic atomic counter delivers that in ~20 ns/id with one allocation,
// versus ~850 ns for a UUIDv7 (which reads crypto/rand and the clock per call),
// a cost that would dominate per-event decoding on the hot path.
var (
	idPrefix  = randPrefix()
	idCounter atomic.Uint64
)

func randPrefix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "ak"
	}
	return "ak" + hex.EncodeToString(b[:])
}

// NewEventID returns a process-unique, time-monotonic event id.
func NewEventID() string {
	n := idCounter.Add(1)
	var buf [40]byte
	out := append(buf[:0], idPrefix...)
	out = append(out, '-')
	out = strconv.AppendUint(out, n, 16)
	return string(out)
}
