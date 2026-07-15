// SPDX-License-Identifier: Apache-2.0
// Package types is the shared data spine for AgentKnox. It has no internal
// dependencies so every component may import it without creating cycles.
package types

import "time"

// Category classifies a system event by the resource domain it touches.
type Category string

const (
	CategoryProcess    Category = "process"
	CategoryFile       Category = "file"
	CategoryNetwork    Category = "network"
	CategoryCapability Category = "capability"
	CategoryDNS        Category = "dns"
	CategoryDatabase   Category = "database"
)

// SyscallEvent is the unified primary system-layer event. It is produced by the
// System Sensor → Decoder/Pairer/Mapper → Enricher.
type SyscallEvent struct {
	// Identity / timing
	EventID     string    `json:"event_id"` // UUIDv7
	TimestampNS uint64    `json:"timestamp_ns"`
	Time        time.Time `json:"time"`
	CPUID       uint32    `json:"cpu_id"`

	// Process identity (host + namespaced)
	HostPPID int32  `json:"host_ppid"`
	HostPID  int32  `json:"host_pid"`
	HostTID  int32  `json:"host_tid"`
	PPID     int32  `json:"ppid"`
	PID      int32  `json:"pid"`
	TID      int32  `json:"tid"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`

	// Kernel attribution keys
	CgroupID uint64 `json:"cgroup_id"`
	PidNS    uint32 `json:"pid_ns"`
	MntNS    uint32 `json:"mnt_ns"`

	// Syscall / semantics
	SyscallID int32  `json:"syscall_id"`
	Name      string `json:"name"`
	Comm      string `json:"comm"`
	ExePath   string `json:"exe_path"`
	RetVal    int64  `json:"ret_val"`

	Category  Category `json:"category"`
	Operation string   `json:"operation"` // exec|read|write|open|connect|...
	Resource  string   `json:"resource"`  // path | addr:port | ...

	// DNS carries parsed DNS query/answer details (DNS-category events only).
	DNS *DNSInfo `json:"dns,omitempty"`

	// Enrichment
	Session *SessionRef `json:"session,omitempty"`
	Meta    *AgentMeta  `json:"meta,omitempty"`
}

// DNSInfo is the parsed content of a DNS query or answer event.
type DNSInfo struct {
	QName   string      `json:"qname"`
	Answers []DNSAnswer `json:"answers,omitempty"` // resolved A/AAAA records (answer events)
}

// DNSAnswer is one resolved address record from a DNS response.
type DNSAnswer struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
}

// SessionRef is a light back-reference attached to events during enrichment.
type SessionRef struct {
	SessionID string    `json:"session_id"`
	Agent     AgentKind `json:"agent"`
}

// AgentMeta carries container/host identity for an event (workstation or k8s).
type AgentMeta struct {
	NodeName    string            `json:"node_name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Pod         string            `json:"pod,omitempty"`
	Container   string            `json:"container,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	Image       string            `json:"image,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}
