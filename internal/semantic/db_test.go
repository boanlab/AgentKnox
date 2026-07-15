// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"encoding/binary"
	"testing"

	"go.uber.org/zap"
)

// --- test byte-buffer builders -------------------------------------------------

// mysqlPacket wraps a command byte + SQL text in a classic MySQL client packet:
// 3-byte little-endian length + 1-byte seq id + payload.
func mysqlPacket(cmd byte, sql string) []byte {
	payload := append([]byte{cmd}, []byte(sql)...)
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), 0x00}
	return append(hdr, payload...)
}

// bsonStr builds a BSON string element (type 0x02).
func bsonStr(key, val string) []byte {
	b := []byte{0x02}
	b = append(b, []byte(key)...)
	b = append(b, 0x00)
	sl := make([]byte, 4)
	binary.LittleEndian.PutUint32(sl, uint32(len(val)+1))
	b = append(b, sl...)
	b = append(b, []byte(val)...)
	b = append(b, 0x00)
	return b
}

// bsonDoc concatenates elements into a BSON document (length prefix + terminator).
func bsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	total := 4 + len(body) + 1
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(total))
	out = append(out, body...)
	return append(out, 0x00)
}

// mongoMsg prepends a 16-byte wire header to a body.
func mongoMsg(opCode int32, body []byte) []byte {
	total := 16 + len(body)
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], uint32(total))
	binary.LittleEndian.PutUint32(b[12:16], uint32(opCode))
	return append(b, body...)
}

// le32Bytes returns a 4-byte little-endian encoding of v.
func le32Bytes(v int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

// --- MySQL ---------------------------------------------------------------------

func TestParseMySQLSelect(t *testing.T) {
	p := New(true, zap.NewNop())
	q := p.ParseDBQuery("mysql", mysqlPacket(mysqlCOMQuery, "SELECT * FROM `users` WHERE id=1"))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Engine != "mysql" || q.Op != "SELECT" || q.Table != "users" || !q.HasWhere {
		t.Fatalf("unexpected query: %+v", q)
	}
	if q.StmtRedact != "SELECT * FROM `users` WHERE id=1" {
		t.Fatalf("capture should retain SQL, got %q", q.StmtRedact)
	}
}

func TestParseMySQLInsert(t *testing.T) {
	p := New(true, zap.NewNop())
	q := p.ParseDBQuery("mysql", mysqlPacket(mysqlCOMQuery, "INSERT INTO orders (id) VALUES (7)"))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "INSERT" || q.Table != "orders" || q.HasWhere {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMySQLStmtPrepareRedaction(t *testing.T) {
	p := New(false, zap.NewNop()) // capturePrompts=false → mask literals
	q := p.ParseDBQuery("mysql", mysqlPacket(mysqlCOMStmtPrepare, "UPDATE users SET name='bob' WHERE id=1"))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "UPDATE" || q.Table != "users" || !q.HasWhere {
		t.Fatalf("unexpected query: %+v", q)
	}
	if q.StmtRedact != "UPDATE users SET name='?' WHERE id=1" {
		t.Fatalf("literal not masked: %q", q.StmtRedact)
	}
}

func TestParseMySQLIgnoredCommand(t *testing.T) {
	p := New(true, zap.NewNop())
	// COM_PING (0x0e) carries no SQL; must be ignored.
	if q := p.ParseDBQuery("mysql", mysqlPacket(0x0e, "")); q != nil {
		t.Fatalf("expected nil for non-query command, got %+v", q)
	}
}

func TestParseMySQLMalformed(t *testing.T) {
	p := New(true, zap.NewNop())
	for _, in := range [][]byte{
		nil,
		{0x01},
		{0x00, 0x00, 0x00, 0x00}, // header only, no command byte
	} {
		if q := p.ParseDBQuery("mysql", in); q != nil {
			t.Fatalf("expected nil for malformed %v, got %+v", in, q)
		}
	}
}

// --- MongoDB -------------------------------------------------------------------

func TestParseMongoOpMsg(t *testing.T) {
	p := New(true, zap.NewNop())
	doc := bsonDoc(bsonStr("find", "sessions"), bsonStr("$db", "app"))
	body := append(le32Bytes(0), 0x00) // flagBits + section kind 0
	body = append(body, doc...)
	q := p.ParseDBQuery("mongodb", mongoMsg(mongoOpMsg, body))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Engine != "mongodb" || q.Op != "find" || q.Table != "sessions" || q.Database != "app" {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMongoOpMsgInsert(t *testing.T) {
	p := New(true, zap.NewNop())
	doc := bsonDoc(bsonStr("insert", "events"), bsonStr("$db", "logs"))
	body := append(le32Bytes(0), 0x00)
	body = append(body, doc...)
	q := p.ParseDBQuery("mongo", mongoMsg(mongoOpMsg, body))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "insert" || q.Table != "events" || q.Database != "logs" {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMongoOpMsgSkipsDocSequence(t *testing.T) {
	p := New(true, zap.NewNop())
	// Kind-1 document-sequence section preceding the kind-0 body.
	ident := append([]byte("documents"), 0x00)
	seqInner := append(ident, bsonDoc(bsonStr("_id", "x"))...)
	seqSize := int32(4 + len(seqInner))
	seq := append(le32Bytes(seqSize), seqInner...)

	doc := bsonDoc(bsonStr("update", "accounts"), bsonStr("$db", "bank"))
	body := le32Bytes(0)        // flagBits
	body = append(body, 0x01)   // section kind 1
	body = append(body, seq...) // document sequence
	body = append(body, 0x00)   // section kind 0
	body = append(body, doc...) // body document

	q := p.ParseDBQuery("mongodb", mongoMsg(mongoOpMsg, body))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "update" || q.Table != "accounts" || q.Database != "bank" {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMongoOpQueryLegacyFind(t *testing.T) {
	p := New(true, zap.NewNop())
	body := le32Bytes(0)                                         // flags
	body = append(body, append([]byte("app.sessions"), 0x00)...) // fullCollectionName
	body = append(body, le32Bytes(0)...)                         // numberToSkip
	body = append(body, le32Bytes(10)...)                        // numberToReturn
	body = append(body, bsonDoc()...)                            // empty query filter
	q := p.ParseDBQuery("mongodb", mongoMsg(mongoOpQuery, body))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "find" || q.Table != "sessions" || q.Database != "app" {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMongoOpQueryCommand(t *testing.T) {
	p := New(true, zap.NewNop())
	doc := bsonDoc(bsonStr("find", "sessions"))
	body := le32Bytes(0)
	body = append(body, append([]byte("app.$cmd"), 0x00)...)
	body = append(body, le32Bytes(0)...)
	body = append(body, le32Bytes(1)...)
	body = append(body, doc...)
	q := p.ParseDBQuery("mongo", mongoMsg(mongoOpQuery, body))
	if q == nil {
		t.Fatal("expected a query, got nil")
	}
	if q.Op != "find" || q.Table != "sessions" || q.Database != "app" {
		t.Fatalf("unexpected query: %+v", q)
	}
}

func TestParseMongoMalformed(t *testing.T) {
	p := New(true, zap.NewNop())
	good := func() []byte {
		doc := bsonDoc(bsonStr("find", "sessions"), bsonStr("$db", "app"))
		body := append(le32Bytes(0), 0x00)
		return mongoMsg(mongoOpMsg, append(body, doc...))
	}
	full := good()
	cases := [][]byte{
		nil,
		{0x01, 0x02},              // shorter than header
		full[:16],                 // header only
		full[:len(full)-3],        // truncated BSON doc
		mongoMsg(9999, []byte{0}), // unknown opcode
	}
	for i, in := range cases {
		if q := p.ParseDBQuery("mongodb", in); q != nil {
			t.Fatalf("case %d: expected nil, got %+v", i, q)
		}
	}
}
