// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgSchema is the aggregator's Postgres schema. Applied idempotently on startup.
const pgSchema = `
CREATE TABLE IF NOT EXISTS events (
	id     BIGSERIAL PRIMARY KEY,
	source TEXT        NOT NULL,
	kind   TEXT        NOT NULL,
	ts     TIMESTAMPTZ NOT NULL,
	data   JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts_idx          ON events (ts);
CREATE INDEX IF NOT EXISTS events_source_kind_idx ON events (source, kind);
`

// pgStore is a Postgres-backed Store. It uses a single mutex-guarded pgx.Conn
// (not pgxpool); serialized access is sufficient for the aggregator's ingest
// workload.
type pgStore struct {
	mu   sync.Mutex
	conn *pgx.Conn
}

// NewPgStore opens a Postgres-backed Store against dsn and runs migrations.
func NewPgStore(ctx context.Context, dsn string) (Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("aggregator: postgres dsn is empty")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("aggregator: connect postgres: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("aggregator: ping postgres: %w", err)
	}
	if _, err := conn.Exec(ctx, pgSchema); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("aggregator: migrate postgres: %w", err)
	}
	return &pgStore{conn: conn}, nil
}

func (s *pgStore) Put(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(recs))
	for _, r := range recs {
		ts := r.Time
		if ts.IsZero() {
			ts = time.Now()
		}
		data := r.Data
		if len(data) == 0 {
			data = []byte("null")
		}
		rows = append(rows, []any{r.Source, r.Kind, ts, []byte(data)})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.CopyFrom(ctx,
		pgx.Identifier{"events"},
		[]string{"source", "kind", "ts", "data"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("aggregator: copy events: %w", err)
	}
	return nil
}

func (s *pgStore) Query(ctx context.Context, f Filter) ([]Record, error) {
	var (
		conds []string
		args  []any
	)
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Source != "" {
		add("source = $%d", f.Source)
	}
	if f.Kind != "" {
		add("kind = $%d", f.Kind)
	}
	if !f.Since.IsZero() {
		add("ts >= $%d", f.Since)
	}
	args = append(args, f.limitOrDefault())
	limitArg := len(args)

	q := "SELECT source, kind, ts, data FROM events"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT $%d", limitArg)

	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.conn.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("aggregator: query events: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var (
			r    Record
			data []byte
		)
		if err := rows.Scan(&r.Source, &r.Kind, &r.Time, &data); err != nil {
			return nil, err
		}
		r.Data = data
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *pgStore) Sources(ctx context.Context) ([]SourceStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.conn.Query(ctx,
		"SELECT source, COUNT(*), MAX(ts) FROM events GROUP BY source ORDER BY source")
	if err != nil {
		return nil, fmt.Errorf("aggregator: query sources: %w", err)
	}
	defer rows.Close()

	var out []SourceStat
	for rows.Next() {
		var st SourceStat
		if err := rows.Scan(&st.Source, &st.Count, &st.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *pgStore) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tag, err := s.conn.Exec(ctx, "DELETE FROM events WHERE ts < $1", olderThan)
	if err != nil {
		return 0, fmt.Errorf("aggregator: prune events: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *pgStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close(context.Background())
}
