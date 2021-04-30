package main

import (
	"strings"
	"testing"
)

func TestUDPQuery(t *testing.T) {
	if err := driver(strings.Split("example.com @1.1.1.1", " ")); err != nil {
		t.Error(err)
	}
}
