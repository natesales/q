package main

import (
	"testing"
)

func TestGetRootHints(t *testing.T) {
	ip4s, ip6s, err := getRootHints()

	if err != nil {
		t.Fatal(err)
	}

	if len(ip4s) == 0 {
		t.Fatal("ipv4 is empty")
	}

	if len(ip6s) == 0 {
		t.Fatal("ipv6 is empty")
	}
}
