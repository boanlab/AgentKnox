// SPDX-License-Identifier: Apache-2.0
package bpf2frame

import "testing"

// buildDNSResponse constructs a minimal DNS response for api.example.com with the
// given A records (IPv4 dotted strings) and a compression pointer to the name.
func buildDNSResponse(ips []byte, count int) []byte {
	// Header: id=0x1234, flags=0x8180 (response, recursion), qd=1, an=count.
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, byte(count >> 8), byte(count), 0x00, 0x00, 0x00, 0x00}
	// Question: 3"api"7"example"3"com"0, QTYPE=A(1), QCLASS=IN(1).
	qname := []byte{3, 'a', 'p', 'i', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg = append(msg, qname...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)
	// Answers: name pointer to offset 12, TYPE=A, CLASS=IN, TTL=300, RDLEN=4, RDATA.
	for i := 0; i < count; i++ {
		msg = append(msg, 0xc0, 0x0c) // pointer to qname at offset 12
		msg = append(msg, 0x00, 0x01, 0x00, 0x01)
		msg = append(msg, 0x00, 0x00, 0x01, 0x2c) // TTL 300
		msg = append(msg, 0x00, 0x04)
		msg = append(msg, ips[i*4:i*4+4]...)
	}
	return msg
}

func TestParseDNSAnswer_A(t *testing.T) {
	ips := []byte{93, 184, 216, 34, 10, 0, 0, 5}
	msg := buildDNSResponse(ips, 2)
	info := parseDNSAnswer(msg)
	if info == nil {
		t.Fatal("parseDNSAnswer returned nil")
	}
	if info.QName != "api.example.com" {
		t.Fatalf("qname = %q, want api.example.com", info.QName)
	}
	if len(info.Answers) != 2 {
		t.Fatalf("answers = %d, want 2", len(info.Answers))
	}
	if info.Answers[0].IP != "93.184.216.34" || info.Answers[0].TTL != 300 {
		t.Fatalf("answer[0] = %+v", info.Answers[0])
	}
	if info.Answers[1].IP != "10.0.0.5" {
		t.Fatalf("answer[1] IP = %q, want 10.0.0.5", info.Answers[1].IP)
	}
}

func TestParseDNSAnswer_RejectsQuery(t *testing.T) {
	// Query (flags QR bit clear) must not parse as an answer.
	msg := buildDNSResponse([]byte{1, 2, 3, 4}, 1)
	msg[2] = 0x01 // clear QR, set RD only
	if info := parseDNSAnswer(msg); info != nil {
		t.Fatalf("query parsed as answer: %+v", info)
	}
}

func TestParseDNSAnswer_Truncated(t *testing.T) {
	if info := parseDNSAnswer([]byte{0x12, 0x34}); info != nil {
		t.Fatalf("truncated payload parsed: %+v", info)
	}
}
