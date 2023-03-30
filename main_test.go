package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMainQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
	}))
}

func TestMainVersion(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-V",
	}))
}

func TestMainODoHQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh1.surfdomeinen.nl",
	}))
}

func TestMainRawFormat(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"--format=raw",
	}))
}

func TestMainJSONFormat(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"--format=json",
	}))
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
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "A",
		"-t", "AAAA",
	}))
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

func TestMainInvalidODoHUpstream(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "tls://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh1.surfdomeinen.nl",
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH target must use HTTPS")
}

func TestMainInvalidODoHProxy(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "tls://odoh1.surfdomeinen.nl",
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH proxy must use HTTPS")
}

func TestMainReverseQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-x",
		"-q", "1.1.1.1",
	}))
}

func TestMainInferredQname(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"example.com",
	}))
}

func TestMainInferredServer(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"@dns.quad9.net",
	}))
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

func TestMainInvalidUpstream(t *testing.T) {
	clearOpts()
	err := driver([]string{
		"-v",
		"-s", "127.127.127.127:1",
		"example.com",
	})
	if !(err != nil && strings.Contains(err.Error(), "connection refused")) {
		t.Errorf("expected connection error, got %+v", err)
	}
}

func TestMainDNSSECArg(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"+dnssec",
		"--format=json",
	}))
}

func TestMainPad(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"--pad",
		"--format=json",
	}))
}

func TestMainChaosClass(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"CH",
		"TXT",
		"--format=json",
	}))
}

func TestMainParsePlusFlags(t *testing.T) {
	clearOpts()
	parsePlusFlags([]string{"+dnssec", "+nord"})
	assert.True(t, opts.DNSSEC)
	assert.False(t, opts.RecursionDesired)
}

func TestMainTCPQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"@tcp://1.1.1.1",
		"--format=json",
	}))
}

func TestMainTLSQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "A",
		"@tls://dns.quad9.net",
		"--format=json",
	}))
}

func TestMainHTTPSQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "A",
		"@https://dns.quad9.net",
		"--format=json",
	}))
}

func TestMainQUICQuery(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"-t", "A",
		"@quic://dns.adguard.com",
		"--format=json",
	}))
}

func TestMainInvalidServerURL(t *testing.T) {
	clearOpts()
	assert.NotNil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"@bad::server::url",
		"--format=json",
	}))
}

func TestMainInvalidTransportScheme(t *testing.T) {
	clearOpts()
	assert.NotNil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"@invalid://example.com",
		"--format=json",
	}))
}

func TestMainTLS12(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"-q", "example.com",
		"--tls-min-version=1.1",
		"--tls-max-version=1.2",
		"@tls://dns.quad9.net",
		"--format=json",
	}))
}

func TestMainNSID(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"@tls://dns.quad9.net",
		"+nsid",
	}))
	// TODO: Remove parentheses
}

func TestMainECSv4(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "192.0.2.0/24",
	}))
}

func TestMainECSv6(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "2001:db8::/48",
	}))
}

func TestMainHTTPUserAgent(t *testing.T) {
	clearOpts()
	assert.Nil(t, driver([]string{
		"-v",
		"@https://dns.quad9.net",
		"--http-user-agent", "Example/1.0",
	}))
}

func TestMainParseServer(t *testing.T) {
	for _, tc := range []struct {
		Server           string
		ExpectedProtocol string
		ExpectedHost     string
	}{
		{ // IPv4 plain with no port
			Server:           "1.1.1.1",
			ExpectedProtocol: "plain",
			ExpectedHost:     "1.1.1.1:53",
		},
		{ // IPv4 plain with explicit port
			Server:           "1.1.1.1:5353",
			ExpectedProtocol: "plain",
			ExpectedHost:     "1.1.1.1:5353",
		},
		{ // IPv6 plain with no port
			Server:           "2a09::",
			ExpectedProtocol: "plain",
			ExpectedHost:     "[2a09::]:53",
		},
		{ // IPv6 plain with explicit port
			Server:           "[2a09::]:5353",
			ExpectedProtocol: "plain",
			ExpectedHost:     "[2a09::]:5353",
		},
		{ // TLS with no port
			Server:           "tls://dns.quad9.net",
			ExpectedProtocol: "tls",
			ExpectedHost:     "dns.quad9.net:853",
		},
		{ // TLS with explicit port
			Server:           "tls://dns.quad9.net:8530",
			ExpectedProtocol: "tls",
			ExpectedHost:     "dns.quad9.net:8530",
		},
		{ // HTTPS with no endpoint
			Server:           "https://dns.quad9.net",
			ExpectedProtocol: "https",
			ExpectedHost:     "https://dns.quad9.net:443/dns-query",
		},
		{ // HTTPS with IPv4 address
			Server:           "https://1.1.1.1",
			ExpectedProtocol: "https",
			ExpectedHost:     "https://1.1.1.1:443/dns-query",
		},
		{ // HTTPS with IPv6 address
			Server:           "https://2a09::",
			ExpectedProtocol: "https",
			ExpectedHost:     "https://[2a09::]:443/dns-query",
		},
		{ // HTTPS with explicit endpoint
			Server:           "https://dns.quad9.net/other-dns-endpoint",
			ExpectedProtocol: "https",
			ExpectedHost:     "https://dns.quad9.net:443/other-dns-endpoint",
		},
		{ // QUIC with no port
			Server:           "quic://dns.adguard.com",
			ExpectedProtocol: "quic",
			ExpectedHost:     "dns.adguard.com:853",
		},
		{ // QUIC with explicit port
			Server:           "quic://dns.adguard.com:8530",
			ExpectedProtocol: "quic",
			ExpectedHost:     "dns.adguard.com:8530",
		},
		{ // IPv6 with scope ID
			Server:           "plain://[fe80::1%en0]:53",
			ExpectedProtocol: "plain",
			ExpectedHost:     "[fe80::1%en0]:53",
		},
	} {
		clearOpts()
		opts.Server = tc.Server
		proto, host, err := parseServer()
		assert.Nilf(t, err, "%s", tc.Server)
		assert.Equalf(t, tc.ExpectedProtocol, proto, "%s", tc.Server)
		assert.Equalf(t, tc.ExpectedHost, host, "%s", tc.Server)
	}
}
