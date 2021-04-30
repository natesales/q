package main

import (
	"strings"
	"testing"
)

func clearOpts() {
	opts.Name = ""
	opts.Server = ""
	opts.Types = []string{}
	opts.Reverse = false
	opts.DNSSEC = false
	opts.Format = "pretty"
	opts.Chaos = false
	opts.OdohProxy = ""
	opts.Insecure = false
	opts.Timeout = 10
	opts.Verbose = false
}

func TestCLIUDPQuery(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"example.com",
	}); err != nil {
		t.Error(err)
	}
}

func TestCLIODOHQuery(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh1.surfdomeinen.nl",
	}); err != nil {
		t.Error(err)
	}
}

func TestRawFormat(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"example.com",
		"--format=raw",
	}); err != nil {
		t.Error(err)
	}
}

func TestJSONFormat(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"example.com",
		"--format=json",
	}); err != nil {
		t.Error(err)
	}
}

func TestInvalidFormat(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"example.com",
		"--format=invalid",
	})
	if !(err != nil && strings.Contains(err.Error(), "invalid output format")) {
		t.Errorf("invalid output format should throw an error")
	}
}

func TestParseTypes(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"example.com",
		"A",
		"AAAA",
	}); err != nil {
		t.Error(err)
	}
}
