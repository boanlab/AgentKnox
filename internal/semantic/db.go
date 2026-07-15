// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"encoding/binary"
	"strings"

	"github.com/boanlab/agentknox/pkg/types"
)

// ParseDBQuery parses a raw database wire-protocol payload (PostgreSQL, MySQL,
// or MongoDB) into a DBQuery. Returns nil when the payload is not a recognized
// query message. The daemon routes a chunk here (via Parser.FeedDB) when the
// process is known to hold a database connection; otherwise chunks go to the
// JSON reassembler.
func (p *Parser) ParseDBQuery(engine string, payload []byte) *types.DBQuery {
	switch strings.ToLower(engine) {
	case "postgres", "postgresql":
		return p.parsePostgres(payload)
	case "mysql":
		return p.parseMySQL(payload)
	case "mongodb", "mongo":
		return p.parseMongo(payload)
	default:
		return nil
	}
}

// parsePostgres implements a minimal PostgreSQL frontend parser for the Simple
// Query message: byte 'Q', an int32 length (big-endian, counting itself but not
// the type byte), then a null-terminated SQL string.
func (p *Parser) parsePostgres(payload []byte) *types.DBQuery {
	// Need at least: 'Q' + int32 len + one byte + null terminator.
	if len(payload) < 6 || payload[0] != 'Q' {
		return nil
	}
	msgLen := int(binary.BigEndian.Uint32(payload[1:5]))
	// The string body is (msgLen-4) bytes following the length field.
	end := 5 + msgLen - 4
	if end < 5 || end > len(payload) {
		end = len(payload)
	}
	sql := strings.TrimSpace(strings.TrimRight(string(payload[5:end]), "\x00"))
	if sql == "" {
		return nil
	}

	q := &types.DBQuery{
		Engine:   "postgres",
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

// sqlTokens splits SQL into whitespace-delimited tokens for naive analysis.
func sqlTokens(sql string) []string {
	return strings.Fields(sql)
}

// sqlOp returns the leading SQL keyword, uppercased (SELECT/INSERT/UPDATE/...).
func sqlOp(sql string) string {
	toks := sqlTokens(sql)
	if len(toks) == 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimLeft(toks[0], "("))
}

// sqlTable naively derives the target table/relation: the token following
// FROM/INTO, or the token after UPDATE.
func sqlTable(sql string) string {
	toks := sqlTokens(sql)
	for i, t := range toks {
		u := strings.ToUpper(t)
		switch u {
		case "FROM", "INTO":
			if i+1 < len(toks) {
				return cleanTable(toks[i+1])
			}
		case "UPDATE":
			if i+1 < len(toks) {
				return cleanTable(toks[i+1])
			}
		}
	}
	return ""
}

// cleanTable strips quoting, trailing punctuation and an opening paren from a
// table token.
func cleanTable(t string) string {
	t = strings.Trim(t, "`\"'();,")
	if idx := strings.IndexAny(t, "("); idx >= 0 {
		t = t[:idx]
	}
	return t
}

// sqlHasWhere reports whether the statement contains a WHERE clause.
func sqlHasWhere(sql string) bool {
	for _, t := range sqlTokens(sql) {
		if strings.ToUpper(t) == "WHERE" {
			return true
		}
	}
	return false
}

// redactSQL masks single-quoted string literals with '?' so a statement can be
// retained for shape/analysis without leaking values.
func redactSQL(sql string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == '\'' {
			if inStr {
				// Handle escaped '' inside a literal.
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
					continue
				}
				inStr = false
				b.WriteByte('\'')
			} else {
				inStr = true
				b.WriteString("'?")
			}
			continue
		}
		if !inStr {
			b.WriteByte(c)
		}
	}
	return b.String()
}
