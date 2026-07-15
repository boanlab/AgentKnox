// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names for the bolt-backed store.
var (
	bucketEvents  = []byte("events")
	bucketSources = []byte("sources")
)

// boltStore is a bbolt-backed Store. Events live in the "events" bucket keyed by
// <big-endian uint64 unixnano><big-endian uint64 seq>: this makes keys sort
// ascending by time (seq breaks ties for same-nanosecond records), so a reverse
// cursor iteration yields newest-first. The value is json.Marshal(Record).
//
// The "sources" bucket holds one entry per source node, source -> JSON
// {count,lastSeenUnixNano}, maintained incrementally on Put so Sources() is a
// cheap scan rather than a full events walk.
type boltStore struct {
	db *bolt.DB
}

// sourceEntry is the persisted per-source aggregate in the sources bucket.
type sourceEntry struct {
	Count            int64 `json:"count"`
	LastSeenUnixNano int64 `json:"lastSeenUnixNano"`
}

// NewBoltStore opens (creating if needed) a bolt-backed Store at path and
// ensures the required buckets exist.
func NewBoltStore(path string) (Store, error) {
	if path == "" {
		return nil, fmt.Errorf("aggregator: bolt path is empty")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("aggregator: open bolt %q: %w", filepath.Clean(path), err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketEvents); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketSources)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("aggregator: init bolt buckets: %w", err)
	}
	return &boltStore{db: db}, nil
}

// eventKey builds the 16-byte sortable key for a record at time t and seq.
func eventKey(unixNano uint64, seq uint64) []byte {
	k := make([]byte, 16)
	binary.BigEndian.PutUint64(k[0:8], unixNano)
	binary.BigEndian.PutUint64(k[8:16], seq)
	return k
}

// keyUnixNano extracts the time component of an event key.
func keyUnixNano(k []byte) int64 {
	if len(k) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(k[0:8]))
}

func (s *boltStore) Put(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		events := tx.Bucket(bucketEvents)
		sources := tx.Bucket(bucketSources)
		if events == nil || sources == nil {
			return fmt.Errorf("aggregator: missing buckets")
		}
		for i := range recs {
			r := recs[i]
			if r.Time.IsZero() {
				r.Time = time.Now()
			}
			val, err := json.Marshal(r)
			if err != nil {
				return fmt.Errorf("aggregator: marshal record: %w", err)
			}
			seq, err := events.NextSequence()
			if err != nil {
				return err
			}
			nano := r.Time.UnixNano()
			if err := events.Put(eventKey(uint64(nano), seq), val); err != nil {
				return err
			}
			if err := bumpSource(sources, r.Source, nano); err != nil {
				return err
			}
		}
		return nil
	})
}

// bumpSource increments the per-source count and advances its last-seen time.
func bumpSource(sources *bolt.Bucket, source string, nano int64) error {
	var e sourceEntry
	if raw := sources.Get([]byte(source)); raw != nil {
		// Best-effort decode; a corrupt entry restarts from zero.
		_ = json.Unmarshal(raw, &e)
	}
	e.Count++
	if nano > e.LastSeenUnixNano {
		e.LastSeenUnixNano = nano
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return sources.Put([]byte(source), buf)
}

func (s *boltStore) Query(ctx context.Context, f Filter) ([]Record, error) {
	limit := f.limitOrDefault()
	out := make([]Record, 0, min(limit, 256))
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvents)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		// Reverse iteration (Last -> Prev) walks newest-first by key layout.
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Since is a lower time bound; keys before it can be skipped wholesale.
			if !f.Since.IsZero() && keyUnixNano(k) < f.Since.UnixNano() {
				break
			}
			var r Record
			if err := json.Unmarshal(v, &r); err != nil {
				continue // skip corrupt value
			}
			if !f.matches(r) {
				continue
			}
			out = append(out, r)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *boltStore) Sources(ctx context.Context) ([]SourceStat, error) {
	var out []SourceStat
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSources)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var e sourceEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil // skip corrupt entry
			}
			st := SourceStat{Source: string(k), Count: e.Count}
			if e.LastSeenUnixNano > 0 {
				st.LastSeen = time.Unix(0, e.LastSeenUnixNano).UTC()
			}
			out = append(out, st)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *boltStore) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	cutoff := olderThan.UnixNano()
	var deleted int64
	err := s.db.Update(func(tx *bolt.Tx) error {
		events := tx.Bucket(bucketEvents)
		sources := tx.Bucket(bucketSources)
		if events == nil {
			return nil
		}
		c := events.Cursor()
		// Keys sort ascending by time, so old records are a contiguous prefix.
		var toDelete [][]byte
		perSource := make(map[string]int64)
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if keyUnixNano(k) >= cutoff {
				break
			}
			// Copy key: it is only valid for the lifetime of the transaction cursor.
			kc := make([]byte, len(k))
			copy(kc, k)
			toDelete = append(toDelete, kc)
			var r Record
			if err := json.Unmarshal(v, &r); err == nil {
				perSource[r.Source]++
			}
		}
		for _, k := range toDelete {
			if err := events.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		if sources != nil {
			decrementSources(sources, perSource)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// decrementSources reduces per-source counts by the pruned amounts, removing a
// source entry once its count reaches zero. LastSeen is intentionally left as-is
// (it reflects the newest record, which is never the one pruned).
func decrementSources(sources *bolt.Bucket, pruned map[string]int64) {
	for src, n := range pruned {
		raw := sources.Get([]byte(src))
		if raw == nil {
			continue
		}
		var e sourceEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		e.Count -= n
		if e.Count <= 0 {
			_ = sources.Delete([]byte(src))
			continue
		}
		if buf, err := json.Marshal(e); err == nil {
			_ = sources.Put([]byte(src), buf)
		}
	}
}

func (s *boltStore) Close() error {
	return s.db.Close()
}
