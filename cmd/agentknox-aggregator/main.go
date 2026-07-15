// SPDX-License-Identifier: Apache-2.0

// Command agentknox-aggregator is the AgentKnox central aggregator: it ingests
// event envelopes forwarded by AgentKnox daemons on many hosts, persists them in
// a pluggable Store (bbolt or Postgres), and exposes a gRPC query API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/aggregator"
)

var version = "dev"

func main() {
	var (
		listenAddr  = flag.String("listen", ":36930", "gRPC listen address (ingest + query)")
		storage     = flag.String("storage", "bolt", "storage backend: bolt|postgres")
		boltPath    = flag.String("bolt-path", "/var/lib/agentknox-aggregator/events.db", "bbolt database path (storage=bolt)")
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN, e.g. postgres://user:pass@host:5432/agentknox (storage=postgres)")
		retention   = flag.Duration("retention", 720*time.Hour, "how long to keep records (0 disables pruning)")
		logLevel    = flag.String("log-level", "info", "log level (debug|info|warn|error)")
	)
	flag.Parse()

	log := newLogger(*logLevel)
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := buildStore(ctx, *storage, *boltPath, *postgresDSN)
	if err != nil {
		log.Fatal("init storage", zap.Error(err))
	}

	cfg := aggregator.Config{
		ListenAddr: *listenAddr,
		Retention:  *retention,
	}
	srv := aggregator.New(store, cfg, log)

	log.Info("agentknox-aggregator starting",
		zap.String("version", version),
		zap.String("storage", *storage),
		zap.String("listen", *listenAddr),
		zap.Duration("retention", *retention),
	)

	if err := srv.Start(ctx); err != nil {
		log.Fatal("run", zap.Error(err))
	}
	log.Info("agentknox-aggregator stopped")
}

// buildStore constructs the Store selected by the storage flag.
func buildStore(ctx context.Context, storage, boltPath, dsn string) (aggregator.Store, error) {
	switch storage {
	case "bolt", "":
		if dir := filepath.Dir(boltPath); dir != "" {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create bolt dir: %w", err)
			}
		}
		return aggregator.NewBoltStore(boltPath)
	case "postgres":
		return aggregator.NewPgStore(ctx, dsn)
	default:
		return nil, fmt.Errorf("unknown storage backend %q (want bolt|postgres)", storage)
	}
}

func newLogger(level string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	l, err := cfg.Build()
	if err != nil {
		l = zap.NewNop()
	}
	return l
}
