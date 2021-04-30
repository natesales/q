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

func TestMainQuery(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainODOHQuery(t *testing.T) {
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

func TestMainRawFormat(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
		"--format=raw",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainJSONFormat(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
		"--format=json",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainInvalidOutputFormat(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"--format=invalid",
	})
	if !(err != nil && strings.Contains(err.Error(), "invalid output format")) {
		t.Errorf("invalid output format should throw an error")
	}
}

func TestMainParseTypes(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "A",
		"-t", "AAAA",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainInvalidTypes(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "INVALID",
	})
	if !(err != nil && strings.Contains(err.Error(), "INVALID is not a valid RR type")) {
		t.Errorf("expected invalid type error, got %+v", err)
	}
}

func TestMainInvalidODOHUpstream(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "tls://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh1.surfdomeinen.nl",
	})
	if !(err != nil && strings.Contains(err.Error(), "doesn't have an explicit HTTPS protocol")) {
		t.Errorf("expected invalid upstream error, got %+v", err)
	}
}

func TestMainInvalidODOHProxy(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "tls://odoh1.surfdomeinen.nl",
	})
	if !(err != nil && strings.Contains(err.Error(), "doesn't have an explicit HTTPS protocol")) {
		t.Errorf("expected proxy error, got %+v", err)
	}
}

func TestMainReverseQuery(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-x",
		"-q", "1.1.1.1",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainInferredQname(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"example.com",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainInferredServer(t *testing.T) {
	clearOpts()
	if err := driver([]string{
		"-v",
		"-q", "example.com",
		"@dns.quad9.net",
	}); err != nil {
		t.Error(err)
	}
}

func TestMainInvalidReverseQuery(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-x",
		"example.com",
	})
	if !(err != nil && strings.Contains(err.Error(), "unrecognized address: example.com")) {
		t.Errorf("expected address error, got %+v", err)
	}
}
