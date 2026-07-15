// SPDX-License-Identifier: Apache-2.0
package bpf2frame

import "testing"

// unixPayload builds the [family u16][zero port u16][sun_path] payload the
// connect hook emits for an AF_UNIX destination.
func unixPayload(path string) []byte {
	p := make([]byte, 4+108)
	p[0], p[1] = 1, 0 // AF_UNIX, little-endian
	copy(p[4:], path)
	return p
}

func TestDecodeSockaddrUnix(t *testing.T) {
	cases := []struct {
		payload []byte
		want    string
	}{
		{unixPayload("/var/run/mysqld/mysqld.sock"), "unix:/var/run/mysqld/mysqld.sock"},
		{unixPayload("/var/run/postgresql/.s.PGSQL.5432"), "unix:/var/run/postgresql/.s.PGSQL.5432"},
		{unixPayload(""), "unix:<abstract>"},
	}
	for _, c := range cases {
		if got := decodeSockaddr(c.payload); got != c.want {
			t.Errorf("decodeSockaddr = %q, want %q", got, c.want)
		}
	}
}

func TestDecodeSockaddrInet(t *testing.T) {
	// AF_INET 203.0.113.5:443 — unchanged by the AF_UNIX case above.
	p := []byte{2, 0, 0x01, 0xbb, 203, 0, 113, 5}
	if got := decodeSockaddr(p); got != "203.0.113.5:443" {
		t.Errorf("decodeSockaddr = %q, want %q", got, "203.0.113.5:443")
	}
}
