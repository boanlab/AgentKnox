// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"strings"

	"github.com/boanlab/agentknox/pkg/types"
)

// MySQL client command bytes we care about.
const (
	mysqlCOMQuery       = 0x03 // COM_QUERY: text-protocol SQL statement
	mysqlCOMStmtPrepare = 0x16 // COM_STMT_PREPARE: prepared-statement text
)

// parseMySQL implements a minimal MySQL client-protocol parser. A MySQL packet
// is: a 3-byte little-endian payload length, a 1-byte sequence id, then the
// payload. The first payload byte is the command; for COM_QUERY and
// COM_STMT_PREPARE the remaining bytes are the SQL text (classic text protocol).
// Other commands are ignored (nil). Malformed input returns nil, never panics.
func (p *Parser) parseMySQL(payload []byte) *types.DBQuery {
	// Need: 3-byte length + seq id + command byte.
	if len(payload) < 5 {
		return nil
	}
	// Little-endian 3-byte payload length (excludes the 4-byte header).
	pktLen := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	body := payload[4:]
	// Trust the smaller of the declared length and what we actually captured, so
	// a truncated/oversized length field cannot drive an out-of-range slice.
	if pktLen >= 1 && pktLen <= len(body) {
		body = body[:pktLen]
	}

	cmd := body[0]
	if cmd != mysqlCOMQuery && cmd != mysqlCOMStmtPrepare {
		return nil
	}
	sql := strings.TrimSpace(string(body[1:]))
	if sql == "" {
		return nil
	}

	q := &types.DBQuery{
		Engine:   "mysql",
		Op:       sqlOp(sql),
		Table:    sqlTable(sql),
		HasWhere: sqlHasWhere(sql),
	}
	if p.capturePrompts {
		q.StmtRedact = sql
	} else {
		q.StmtRedact = redactSQL(sql)
	}
	return q
}
