<!-- SPDX-License-Identifier: Apache-2.0 -->
# Central Aggregator (Multi-Host)

A single AgentKnox daemon logs and serves its events locally: a JSONL write-ahead log under `walDir`, plus the `AgentKnoxExport` gRPC API on `:36920`. When you run AgentKnox on **many hosts**, the aggregator gives you one place to collect and query all of them, backed by a database. By the end of this document you will have the aggregator running, every daemon forwarding to it, and a working query.

For installing the daemon itself, see [installation.md](installation.md). For the `aggregatorAddr` key, see [configuration.md](configuration.md#config-keys).

```
 host A  agentknox ─┐
 host B  agentknox ─┼─ gRPC Ingest ─▶  aggregator (:36930)  ──▶  DB (bbolt | PostgreSQL)
 host C  agentknox ─┘                    │
                                         └─ Query / Sources RPCs
```

---

## Table of Contents

- [What the Aggregator Is](#what-the-aggregator-is)
- [Step 1 — Run the Aggregator](#step-1--run-the-aggregator)
- [Step 2 — Point Each Daemon at It](#step-2--point-each-daemon-at-it)
- [Step 3 — Query Collected Events](#step-3--query-collected-events)
- [Aggregator Flags](#aggregator-flags)
- [Operational Notes](#operational-notes)

---

## What the Aggregator Is

`bin/agentknox-aggregator` is a plain network service: no eBPF, no privileges, no kernel requirements. It serves the `AgentKnoxAggregator` gRPC service defined in [`../protobuf/agentknox.proto`](../protobuf/agentknox.proto), plus the standard gRPC health service:

| RPC | Purpose |
|---|---|
| `Ingest` | Daemons forward batches of event envelopes here, tagged with the sender's `nodeName` |
| `Query` | Filter collected events by `source`, `kind`, `since_unix_nano`, and `limit` |
| `Sources` | Which hosts are reporting, how many events each has sent, and when each was last seen |

Storage is pluggable: **bbolt** (embedded, single file, no external dependency) or **PostgreSQL** (queryable, shared, retained; the choice for a real fleet).

Build it with `make aggregator`, or as part of `make build`.

---

## Step 1 — Run the Aggregator

Deploy this on **one** central host.

### Option A — Docker Compose (aggregator + PostgreSQL)

```bash
docker compose -f deployments/aggregator/docker-compose.yaml up --build -d
```

- Ingest and query gRPC API published on `:36930`.
- PostgreSQL 16 in a sidecar; data persists in the `agentknox-pgdata` volume.
- Retention defaults to `720h` (30 days).
- The aggregator waits on the database's health check before starting.

The compose file hardcodes the development DSN `postgres://agentknox:agentknox@postgres:5432/agentknox?sslmode=disable`. Change the credentials before using it anywhere real.

### Option B — systemd (embedded bbolt, no external database)

For a single central host without Docker:

```bash
sudo install -m0755 bin/agentknox-aggregator /usr/local/bin/agentknox-aggregator
sudo cp deployments/systemd/agentknox-aggregator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agentknox-aggregator
```

The shipped unit runs unprivileged: `DynamicUser=yes`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, and a `StateDirectory=agentknox-aggregator`, so `events.db` lands under `/var/lib/agentknox-aggregator/`. It starts the binary with `--listen=:36930 --storage=bolt --retention=720h`.

Confirm it is up:

```bash
systemctl status agentknox-aggregator
journalctl -u agentknox-aggregator -f
# Expect: agentknox-aggregator starting  storage=bolt listen=:36930 retention=720h
```

---

## Step 2 — Point Each Daemon at It

On every monitored host, set `aggregatorAddr` in `agentknox.yaml`:

```yaml
# /etc/agentknox/agentknox.yaml
aggregatorAddr: aggregator-host:36930
```

This key is **hot-reloaded**. The daemon watches the directory holding its config file and starts, stops, or redirects forwarding without a restart; look for:

```
aggregator target changed   old=... new=aggregator-host:36930
```

Hot-reload needs a config *file* to watch, so a deployment configured purely through `AGENTKNOX_*` environment variables has to restart to change the target.

The daemon batches envelopes and sends them over `Ingest`, flushing at 256 envelopes or every 2 seconds, whichever comes first. **Forwarding is best-effort and non-blocking**: if the aggregator is unreachable or the send queue is full, events are dropped rather than stalling the pipeline. The local WAL and the local gRPC API keep working regardless, so nothing that matters for enforcement depends on the aggregator being up.

---

## Step 3 — Query Collected Events

Queries go over the `AgentKnoxAggregator` gRPC service, programmatically with any client generated from the proto file, or ad hoc with [`grpcurl`](https://github.com/fullstorydev/grpcurl). The server does not enable reflection, so pass the proto file explicitly:

```bash
# Recent alerts from all hosts
grpcurl -plaintext -proto protobuf/agentknox.proto \
  -d '{"kind":"alert","limit":50}' \
  aggregator-host:36930 agentknox.v1.AgentKnoxAggregator/Query

# Everything from one host since a timestamp (since_unix_nano, in nanoseconds)
grpcurl -plaintext -proto protobuf/agentknox.proto \
  -d '{"source":"web-01","since_unix_nano":1784332800000000000}' \
  aggregator-host:36930 agentknox.v1.AgentKnoxAggregator/Query

# Which hosts are reporting, how many events each, and when last seen
grpcurl -plaintext -proto protobuf/agentknox.proto \
  aggregator-host:36930 agentknox.v1.AgentKnoxAggregator/Sources
```

| `Query` field | Meaning |
|---|---|
| `source` | Node name of the sending daemon (its `nodeName`); empty matches all |
| `kind` | Envelope kind: `syscall`, `semantic`, `action`, `alert`, `edge`; empty matches all |
| `since_unix_nano` | Lower time bound in nanoseconds; `0` means unbounded |
| `limit` | Maximum records to return |

Each returned `Record` carries `source`, `kind`, `time_unix_nano`, and the envelope `data` as raw JSON, the same payload `akctl stream` prints locally.

> `akctl` is a client of the **daemon's** `AgentKnoxExport` service, not of the aggregator. Use `grpcurl` or your own client for aggregator queries.

---

## Aggregator Flags

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `:36930` | gRPC listen address (ingest + query + health) |
| `--storage` | `bolt` | `bolt` (embedded) or `postgres` |
| `--bolt-path` | `/var/lib/agentknox-aggregator/events.db` | bbolt file; the parent directory is created if missing (`--storage=bolt`) |
| `--postgres-dsn` | *(empty)* | For example `postgres://user:pass@host:5432/agentknox?sslmode=disable` (`--storage=postgres`) |
| `--retention` | `720h` | Delete records older than this; `0` disables pruning |
| `--log-level` | `info` | `debug`, `info`, `warn`, or `error` |

The retention prune loop runs hourly and logs what it removed:

```
aggregator: pruned old records   deleted=... cutoff=...
```

---

## Operational Notes

- **Ingest is unauthenticated by default and speaks plaintext gRPC.** Keep the aggregator on a trusted network, or put it behind your own TLS-terminating reverse proxy with authentication before exposing it.
- **Choose the store for the workload.** bbolt is the right answer for simple single-node collection with no dependency to operate. PostgreSQL is the right answer for a fleet: shared, queryable, and retained.
- **The aggregator is not on the enforcement path.** It collects and serves history. Every policy decision is taken and applied on the monitored host, so an aggregator outage costs visibility, never enforcement.
- **Prompt and response text may be forwarded.** With `capturePrompts: true` on a monitored host, semantic envelopes carry captured text, and forwarding sends them off that host. Set `capturePrompts: false` on hosts where that is not acceptable.

---

## See also

- [configuration.md](configuration.md#config-keys) — `aggregatorAddr`, `nodeName`, `capturePrompts`
- [installation.md](installation.md) — installing the daemon on each monitored host
- [troubleshooting.md](troubleshooting.md#aggregator-forwarding) — when events do not arrive
- [`../protobuf/agentknox.proto`](../protobuf/agentknox.proto) — the gRPC contract

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
