// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

// TestDBEngineForResource covers both destination forms a database client can
// take: a remote server on a well-known port, and a local server reached over a
// unix socket (which carries no port at all, so the socket name is the signal).
func TestDBEngineForResource(t *testing.T) {
	cases := []struct {
		resource string
		engine   string
		ok       bool
	}{
		{"10.0.0.5:5432", "postgres", true},
		{"10.0.0.5:3306", "mysql", true},
		{"[2001:db8::1]:27017", "mongodb", true},
		{"10.0.0.5:443", "", false},
		{"unix:/var/run/mysqld/mysqld.sock", "mysql", true},
		{"unix:/run/postgresql/.s.PGSQL.5432", "postgres", true},
		{"unix:/tmp/mongodb-27017.sock", "mongodb", true},
		{"unix:/var/run/docker.sock", "", false},
		{"unix:<abstract>", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		engine, ok := dbEngineForResource(c.resource)
		if ok != c.ok || engine != c.engine {
			t.Errorf("dbEngineForResource(%q) = (%q, %v), want (%q, %v)",
				c.resource, engine, ok, c.engine, c.ok)
		}
	}
}
