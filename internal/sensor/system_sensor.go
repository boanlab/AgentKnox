// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/pkg/types"
)

// SystemSensor reads the ak_events ring and emits decoded SyscallEvents.
// It implements pipeline.SystemSensor.
type SystemSensor struct {
	loader  *Loader
	log     *zap.Logger
	reader  *ringbuf.Reader
	out     chan types.SyscallEvent
	dropped uint64 // events discarded because the consumer fell behind (loop goroutine only)
}

// dropReportEvery rate-limits the drop warning: the first drop and every
// dropReportEvery-th afterwards are reported with the running total.
const dropReportEvery = 1000

func NewSystemSensor(l *Loader, log *zap.Logger) *SystemSensor {
	return &SystemSensor{loader: l, log: log, out: make(chan types.SyscallEvent, 8192)}
}

func (s *SystemSensor) Start(ctx context.Context) (<-chan types.SyscallEvent, error) {
	rd, err := ringbuf.NewReader(s.loader.EventsMap())
	if err != nil {
		return nil, err
	}
	s.reader = rd
	go s.loop(ctx)
	return s.out, nil
}

func (s *SystemSensor) loop(ctx context.Context) {
	defer close(s.out)
	go func() {
		<-ctx.Done()
		_ = s.reader.Close()
	}()
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		f, err := bpf2frame.Decode(rec.RawSample)
		if err != nil {
			continue
		}
		ev := bpf2frame.MapSyscall(f)
		select {
		case s.out <- ev:
		default:
			// A drop is a gap in the observed stream, so it is reported rather than
			// left at debug level; the running total is rate-limited, not the fact.
			s.dropped++
			if s.dropped%dropReportEvery == 1 {
				s.log.Warn("system sensor: event dropped, consumer slow; observation has gaps",
					zap.Uint64("dropped_total", s.dropped))
			}
		}
	}
}

// RegisterSession / RegisterPID set the MONITOR flag only (always safe, works
// without a BPF-LSM backend). The enforcer separately upgrades these keys with
// the ENFORCE flag. Registering by pid scopes capture to the agent's process
// tree even when the cgroup is shared.
func (s *SystemSensor) RegisterSession(cgroupID uint64) {
	if cgroupID == 0 {
		return
	}
	if err := s.loader.RegisterSession(cgroupID, false); err != nil {
		// A rejected registration means the cgroup is not in the capture domain at
		// all, so its activity is neither observed nor attributed. Never silent.
		s.log.Warn("system sensor: register session cgroup failed; the cgroup is NOT monitored",
			zap.Uint64("cgroup", cgroupID), zap.Error(err))
	}
}

func (s *SystemSensor) UnregisterSession(cgroupID uint64) {
	if cgroupID != 0 {
		_ = s.loader.UnregisterSession(cgroupID)
	}
}

func (s *SystemSensor) RegisterPID(pid int32) {
	if pid <= 0 {
		return
	}
	if err := s.loader.RegisterPID(uint32(pid), false); err != nil {
		s.log.Warn("system sensor: register pid failed; the process is NOT monitored",
			zap.Int32("pid", pid), zap.Error(err))
	}
}

func (s *SystemSensor) UnregisterPID(pid int32) {
	if pid > 0 {
		_ = s.loader.UnregisterPID(uint32(pid))
	}
}

func (s *SystemSensor) Close() error {
	if s.reader != nil {
		return s.reader.Close()
	}
	return nil
}
