// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

// dbPortEngines maps a well-known database port to its wire-protocol engine.
var dbPortEngines = map[int]string{
	5432:  "postgres",
	3306:  "mysql",
	27017: "mongodb",
	27018: "mongodb",
	27019: "mongodb",
}

// dbConn is a pid's database association: wire-protocol engine + endpoint.
type dbConn struct {
	engine   string
	endpoint string // "ip:port" from the observed connect
}

// noteDBConnect records a session process that connected to a database port, so
// its captured plaintext chunks are routed to the DB wire parser rather than the
// JSON reassembler. Called from the connect path of handleSyscalls.
func (d *Daemon) noteDBConnect(pid int32, resource string) {
	engine, ok := dbEngineForResource(resource)
	if !ok {
		return
	}
	d.dbMu.Lock()
	if d.dbPids[pid].engine != engine {
		d.dbPids[pid] = dbConn{engine: engine, endpoint: resource}
		d.log.Debug("db: routing pid's semantic chunks to wire parser",
			zap.String("engine", engine), zap.Int32("pid", pid))
	}
	d.dbMu.Unlock()
}

// dbEngine returns the DB connection a pid is talking to, if any.
func (d *Daemon) dbEngine(pid int32) (dbConn, bool) {
	d.dbMu.Lock()
	c, ok := d.dbPids[pid]
	d.dbMu.Unlock()
	return c, ok
}

// forgetDB drops a pid's DB association (on process/session exit).
func (d *Daemon) forgetDB(pid int32) {
	d.dbMu.Lock()
	delete(d.dbPids, pid)
	d.dbMu.Unlock()
}

// dbSocketEngines maps a lowercase token in a unix socket path to its wire
// protocol. A local client reaching its server over /var/run carries no port, so
// the server socket name is what identifies the protocol (mysqld.sock,
// .s.PGSQL.5432, mongodb-27017.sock). The kernel registers such a socket for
// capture on the same tokens (ak_unix_db_sock).
var dbSocketEngines = []struct {
	token  string
	engine string
}{
	{"mysql", "mysql"},
	{"pgsql", "postgres"},
	{"mongo", "mongodb"},
}

// dbEngineForResource parses a connect resource and returns the DB engine it
// names: an "ip:port" (or "[ipv6]:port") on a well-known database port, or a
// "unix:<path>" naming a database server's socket.
func dbEngineForResource(resource string) (string, bool) {
	if path, ok := strings.CutPrefix(resource, "unix:"); ok {
		lp := strings.ToLower(path)
		for _, s := range dbSocketEngines {
			if strings.Contains(lp, s.token) {
				return s.engine, true
			}
		}
		return "", false
	}
	i := strings.LastIndex(resource, ":")
	if i < 0 || i+1 >= len(resource) {
		return "", false
	}
	port, err := strconv.Atoi(resource[i+1:])
	if err != nil {
		return "", false
	}
	engine, ok := dbPortEngines[port]
	return engine, ok
}

// isConnect reports whether an event is an outbound-connection observation
// (either the connect syscall or the LSM socket_connect visibility event).
func isConnect(e *types.SyscallEvent) bool {
	return e.Category == types.CategoryNetwork && e.Operation == "connect"
}
