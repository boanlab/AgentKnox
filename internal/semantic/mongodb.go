// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/boanlab/agentknox/pkg/types"
)

// MongoDB wire-protocol opcodes we handle.
const (
	mongoOpQuery = 2004 // legacy OP_QUERY
	mongoOpMsg   = 2013 // OP_MSG (modern command protocol)
)

// parseMongo implements a minimal MongoDB wire-protocol parser. Every message
// starts with a 16-byte header of four little-endian int32s: messageLength,
// requestID, responseTo, opCode. The body depends on opCode. Only OP_MSG and
// OP_QUERY carry a command document we can inspect; anything else returns nil.
// The parser is defensive: it bounds-checks every field and returns nil (never
// panics) on malformed input.
func (p *Parser) parseMongo(payload []byte) *types.DBQuery {
	if len(payload) < 16 {
		return nil
	}
	msgLen := int(le32(payload[0:4]))
	opCode := le32(payload[12:16])

	body := payload
	// Trust the smaller of the declared length and what we captured.
	if msgLen >= 16 && msgLen <= len(payload) {
		body = payload[:msgLen]
	}
	rest := body[16:]

	switch opCode {
	case mongoOpMsg:
		return p.parseMongoOpMsg(rest)
	case mongoOpQuery:
		return p.parseMongoOpQuery(rest)
	default:
		return nil
	}
}

// parseMongoOpMsg parses an OP_MSG body: a 4-byte flagBits, then one or more
// sections. A kind-0 section is a single BSON body document; a kind-1 section is
// a length-prefixed document sequence which we skip while searching for the
// body.
func (p *Parser) parseMongoOpMsg(rest []byte) *types.DBQuery {
	if len(rest) < 4 {
		return nil
	}
	rest = rest[4:] // flagBits

	for len(rest) >= 1 {
		kind := rest[0]
		rest = rest[1:]
		switch kind {
		case 0: // body: a single BSON document
			op, coll, db := mongoCommandFromDoc(rest)
			return p.mkMongoQuery(op, coll, db)
		case 1: // document sequence: int32 size (incl itself) + identifier + docs
			if len(rest) < 4 {
				return nil
			}
			size := int(le32(rest[0:4]))
			if size < 4 || size > len(rest) {
				return nil
			}
			rest = rest[size:]
		default:
			return nil
		}
	}
	return nil
}

// parseMongoOpQuery parses a legacy OP_QUERY body: int32 flags, a
// fullCollectionName cstring ("db.collection"), int32 numberToSkip, int32
// numberToReturn, then the query BSON document. Commands travel on the "db.$cmd"
// pseudo-collection with the command in the query doc; a plain collection name
// is a legacy find whose query doc is the filter.
func (p *Parser) parseMongoOpQuery(rest []byte) *types.DBQuery {
	if len(rest) < 4 {
		return nil
	}
	rest = rest[4:] // flags

	end := bytes.IndexByte(rest, 0x00)
	if end < 0 {
		return nil
	}
	fullName := string(rest[:end])
	rest = rest[end+1:]
	if len(rest) < 8 {
		return nil
	}
	rest = rest[8:] // numberToSkip + numberToReturn

	op, coll, db := mongoCommandFromDoc(rest)

	fdb, fcoll := "", fullName
	if dot := strings.IndexByte(fullName, '.'); dot >= 0 {
		fdb, fcoll = fullName[:dot], fullName[dot+1:]
	}
	if db == "" {
		db = fdb
	}
	if fcoll == "$cmd" {
		// The command document carries the real op + target collection.
		return p.mkMongoQuery(op, coll, db)
	}
	// Legacy find against a concrete collection.
	return p.mkMongoQuery("find", fcoll, db)
}

// mkMongoQuery assembles a DBQuery, returning nil when no operation was found.
func (p *Parser) mkMongoQuery(op, coll, db string) *types.DBQuery {
	if op == "" {
		return nil
	}
	return &types.DBQuery{
		Engine:   "mongodb",
		Op:       op,
		Table:    coll,
		Database: db,
	}
}

// mongoCommandFromDoc reads a BSON command document. By convention the first
// element's key is the command name and (for string-valued commands like
// find/insert/update) its value is the target collection. A top-level "$db"
// string names the database.
func mongoCommandFromDoc(doc []byte) (op, coll, db string) {
	first := true
	bsonScan(doc, func(key string, typ byte, val []byte) bool {
		if first {
			first = false
			op = key
			if typ == bsonString02 {
				coll = readBSONString(val)
			}
		}
		if key == "$db" && typ == bsonString02 {
			db = readBSONString(val)
		}
		return true // keep scanning so a later $db is still found
	})
	return op, coll, db
}

// BSON element type bytes referenced by the scanner.
const (
	bsonString02 = 0x02
)

// bsonScan walks the top-level elements of a BSON document (bytes begin with the
// int32 document length) and invokes visit for each. It stops early if visit
// returns false and silently aborts on any malformed/out-of-bounds structure.
func bsonScan(doc []byte, visit func(key string, typ byte, val []byte) bool) {
	if len(doc) < 5 {
		return
	}
	total := int(le32(doc[0:4]))
	if total < 5 || total > len(doc) {
		return
	}
	d := doc[:total]

	i := 4
	for i < len(d) {
		typ := d[i]
		if typ == 0x00 { // document terminator
			return
		}
		i++
		// cstring key.
		rel := bytes.IndexByte(d[i:], 0x00)
		if rel < 0 {
			return
		}
		key := string(d[i : i+rel])
		i += rel + 1
		if i > len(d) {
			return
		}
		vlen, ok := bsonValueLen(typ, d[i:])
		if !ok || i+vlen > len(d) {
			return
		}
		if !visit(key, typ, d[i:i+vlen]) {
			return
		}
		i += vlen
	}
}

// bsonValueLen returns the byte length of a BSON value of the given type given
// the bytes starting at the value. ok is false for unknown types or when the
// value's own length header runs past the buffer.
func bsonValueLen(typ byte, b []byte) (int, bool) {
	switch typ {
	case 0x0A, 0x06, 0xFF, 0x7F: // null, undefined, min key, max key
		return 0, true
	case 0x08: // bool
		return 1, true
	case 0x10: // int32
		return 4, true
	case 0x01, 0x09, 0x11, 0x12: // double, datetime, timestamp, int64
		return 8, true
	case 0x07: // ObjectId
		return 12, true
	case 0x13: // decimal128
		return 16, true
	case 0x02, 0x0D, 0x0E: // string, JavaScript, symbol
		if len(b) < 4 {
			return 0, false
		}
		strLen := int(le32(b[0:4]))
		total := 4 + strLen
		if strLen < 1 || total > len(b) {
			return 0, false
		}
		return total, true
	case 0x03, 0x04: // embedded document, array
		if len(b) < 4 {
			return 0, false
		}
		dl := int(le32(b[0:4]))
		if dl < 5 || dl > len(b) {
			return 0, false
		}
		return dl, true
	case 0x05: // binary
		if len(b) < 5 {
			return 0, false
		}
		bl := int(le32(b[0:4]))
		total := 4 + 1 + bl
		if bl < 0 || total > len(b) {
			return 0, false
		}
		return total, true
	default:
		return 0, false
	}
}

// readBSONString decodes a BSON string value (int32 length including the
// trailing NUL, then the bytes). Returns "" on malformed input.
func readBSONString(val []byte) string {
	if len(val) < 4 {
		return ""
	}
	n := int(le32(val[0:4]))
	if n < 1 || 4+n > len(val) {
		return ""
	}
	return string(val[4 : 4+n-1]) // drop the trailing NUL
}

// le32 reads a little-endian int32. Callers must ensure len(b) >= 4.
func le32(b []byte) int32 {
	return int32(binary.LittleEndian.Uint32(b))
}
