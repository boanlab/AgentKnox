// SPDX-License-Identifier: Apache-2.0
// Command agentknox is the AgentKnox daemon: it monitors and enforces policy on
// AI coding agents at the host kernel boundary, without modifying the agents.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/config"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "offsetdb" {
		if err := runOffsetDB(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "offsetdb:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	logLevel := flag.String("log-level", "", "log level (debug|info|warn|error)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	log := newLogger(cfg.LogLevel)
	defer func() { _ = log.Sync() }()
	log.Info("agentknox starting", zap.String("version", version), zap.String("mode", string(cfg.Mode)))

	if os.Geteuid() != 0 {
		log.Warn("not running as root; eBPF load and LSM enforcement will likely fail")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	d, err := NewDaemon(cfg, log)
	if err != nil {
		log.Fatal("init", zap.Error(err))
	}
	if err := d.Run(ctx); err != nil {
		log.Fatal("run", zap.Error(err))
	}
	log.Info("agentknox stopped")
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
