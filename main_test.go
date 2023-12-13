package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
)

func TestMainQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* TXT "v=spf1 -all"`), out.String())
}

func TestMainVersion(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"-V",
	}, &out))
	assert.Contains(t, out.String(), "https://github.com/natesales/q version dev (unknown unknown)")
}

// TODO
// func TestMainODoHQuery(t *testing.T) {
// 	clearOpts()
// 	assert.Nil(t, driver([]string{
// 		"--all",
// 		"-q", "example.com",
// 		"-s", "https://odoh.cloudflare-dns.com",
// 		"--odoh-proxy", "https://odoh.crypto.sx",
// 	}, &out))
// }

func TestMainRawFormat(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"--format=raw",
	}, &out))
	assert.Contains(t, out.String(), "v=spf1 -all")
	assert.Contains(t, out.String(), "a.iana-servers.net")
}

func TestMainJSONFormat(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"--format=json",
	}, &out))
	assert.Contains(t, out.String(), `"Preference":0,"Mx":"."`)
	assert.Contains(t, out.String(), `"Ns":"a.iana-servers.net."`)
	assert.Contains(t, out.String(), `"Txt":["v=spf1 -all"]`)
}

func TestMainInvalidOutputFormat(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-q", "example.com",
		"--format=invalid",
	}, &out)
	if !(err != nil && strings.Contains(err.Error(), "invalid output format")) {
		t.Errorf("invalid output format should throw an error")
	}
}

func TestMainParseTypes(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"-t", "A",
		"-t", "AAAA",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
	assert.Regexp(t, regexp.MustCompile(`example.com. .* AAAA .*`), out.String())
}

func TestMainInvalidTypes(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-q", "example.com",
		"-t", "INVALID",
	}, &out)
	if !(err != nil && strings.Contains(err.Error(), "INVALID is not a valid RR type")) {
		t.Errorf("expected invalid type error, got %+v", err)
	}
}

func TestMainInvalidODoHUpstream(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-q", "example.com",
		"-s", "tls://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh.crypto.sx",
	}, &out)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH target must use HTTPS")
}

func TestMainInvalidODoHProxy(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "tls://odoh1.surfdomeinen.nl",
	}, &out)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH proxy must use HTTPS")
}

func TestMainReverseQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-x",
		"-q", "1.1.1.1",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`1.1.1.1.in-addr.arpa. .* PTR one.one.one.one`), out.String())
}

func TestMainInferredQname(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"example.com",
		"A",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInferredServer(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"@8.8.8.8",
		"-t", "A",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidReverseQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-x",
		"example.com",
	}, &out)
	if !(err != nil && strings.Contains(err.Error(), "unrecognized address: example.com")) {
		t.Errorf("expected address error, got %+v", err)
	}
}

func TestMainInvalidUpstream(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	err := driver([]string{
		"--all",
		"-s", "127.127.127.127:1",
		"example.com",
	}, &out)
	if !(err != nil && strings.Contains(err.Error(), "connection refused")) {
		t.Errorf("expected connection error, got %+v", err)
	}
}

func TestMainDNSSECArg(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"example.com",
		"+dnssec",
		"@9.9.9.9",
	}, &out))
	t.Logf("out: %s", out.String())
	assert.Regexp(t, regexp.MustCompile(`example.com. .* RRSIG .*`), out.String())
}

func TestMainPad(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"--pad",
		"--format=json",
	}, &out))
	assert.Contains(t, out.String(), `"Truncated":false`)
}

func TestMainChaosClass(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"id.server",
		"CH",
		"TXT",
		"@9.9.9.9",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`id.server. .* TXT ".*.pch.net"`), out.String())
}

func TestMainParsePlusFlags(t *testing.T) {
	clearOpts()
	cli.ParsePlusFlags(&opts, []string{"+dnssec", "+nord"})
	assert.True(t, opts.DNSSEC)
	assert.False(t, opts.RecursionDesired)
}

func TestMainTCPQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-t", "A",
		"-q", "example.com",
		"@tcp://1.1.1.1",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLSQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@tls://1.1.1.1",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainHTTPSQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@https://dns.quad9.net",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainQUICQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@quic://dns.adguard.com",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptStampQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"-q", "example.com",
		"-t", "A",
		"@sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptManualQuery(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"-q", "example.com",
		"-t", "A",
		"@dnscrypt://94.140.14.14:5443",
		"--dnscrypt-key", "d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873",
		"--dnscrypt-provider", "2.dnscrypt.default.ns1.adguard.com",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidServerURL(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.NotNil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"@bad::server::url",
		"--format=json",
	}, &out))
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidTransportScheme(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.NotNil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"@invalid://example.com",
		"--format=json",
	}, &out))
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLS12(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"-q", "example.com",
		"--tls-min-version=1.1",
		"--tls-max-version=1.2",
		"@tls://dns.quad9.net",
		"-t", "A",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainNSID(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"@9.9.9.9",
		"+nsid",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`.*.pch.net.*`), out.String())
}

func TestMainECSv4(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "192.0.2.0/24",
	}, &out))
	assert.Contains(t, out.String(), `'subnet':'192.0.2.0/24/0'`)
}

func TestMainECSv6(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "2001:db8::/48",
	}, &out))
	assert.Contains(t, out.String(), `'subnet':'[2001:db8::]/48/0'`)
}

func TestMainHTTPUserAgent(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"@https://dns.quad9.net",
		"--http-user-agent", "Example/1.0",
		"-t", "NS",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`. .* NS a.root-servers.net.`), out.String())
}

func TestMainParseServer(t *testing.T) {
	for _, tc := range []struct {
		Server       string
		Type         transport.Type
		ExpectedHost string
	}{
		{ // IPv4 plain with no port
			Server:       "1.1.1.1",
			Type:         transport.TypePlain,
			ExpectedHost: "1.1.1.1:53",
		},
		{ // IPv4 plain with explicit port
			Server:       "1.1.1.1:5353",
			Type:         transport.TypePlain,
			ExpectedHost: "1.1.1.1:5353",
		},
		{ // IPv6 plain with no port
			Server:       "2a09::",
			Type:         transport.TypePlain,
			ExpectedHost: "[2a09::]:53",
		},
		{ // IPv6 plain with explicit port
			Server:       "[2a09::]:5353",
			Type:         transport.TypePlain,
			ExpectedHost: "[2a09::]:5353",
		},
		{ // TLS with no port
			Server:       "tls://dns.quad9.net",
			Type:         transport.TypeTLS,
			ExpectedHost: "dns.quad9.net:853",
		},
		{ // TLS with explicit port
			Server:       "tls://dns.quad9.net:8530",
			Type:         transport.TypeTLS,
			ExpectedHost: "dns.quad9.net:8530",
		},
		{ // HTTPS with no endpoint
			Server:       "https://dns.quad9.net",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://dns.quad9.net:443/dns-query",
		},
		{ // HTTPS with IPv4 address
			Server:       "https://1.1.1.1",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://1.1.1.1:443/dns-query",
		},
		{ // TCP with no port
			Server:       "tcp://dns.quad9.net",
			Type:         transport.TypeTCP,
			ExpectedHost: "dns.quad9.net:53",
		},
		{ // HTTPS with IPv6 address
			Server:       "https://2a09::",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://[2a09::]:443/dns-query",
		},
		{ // HTTPS with explicit endpoint
			Server:       "https://dns.quad9.net/other-dns-endpoint",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://dns.quad9.net:443/other-dns-endpoint",
		},
		{ // QUIC with no port
			Server:       "quic://dns.adguard.com",
			Type:         transport.TypeQUIC,
			ExpectedHost: "dns.adguard.com:853",
		},
		{ // QUIC with explicit port
			Server:       "quic://dns.adguard.com:8530",
			Type:         transport.TypeQUIC,
			ExpectedHost: "dns.adguard.com:8530",
		},
		{ // IPv6 with scope ID and explicit port
			Server:       "plain://[fe80::1%en0]:53",
			Type:         transport.TypePlain,
			ExpectedHost: "[fe80::1%en0]:53",
		},
		{ // DNS Stamp
			Server:       "sdns://AgcAAAAAAAAAAAAHOS45LjkuOQA",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://9.9.9.9:443/dns-query",
		},
		{ // URL encoded path (https://github.com/natesales/q/issues/66)
			Server:       "https://localhost/1%3A89%3D%3D%3A64fx",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://localhost:443/1%3A89%3D%3D%3A64fx",
		},
		{ // Colons in URL path (https://github.com/natesales/q/issues/66)
			Server:       "https://localhost/1:89==:64fx",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://localhost:443/1:89==:64fx",
		},
		{ // Plain IPv6 address
			Server:       "2001:db8:11:8340:dea6:32ff:fe5b:a19e",
			Type:         transport.TypePlain,
			ExpectedHost: "[2001:db8:11:8340:dea6:32ff:fe5b:a19e]:53",
		},
	} {
		t.Run(tc.Server, func(t *testing.T) {
			server, transportType, err := parseServer(tc.Server)
			assert.Nil(t, err)
			assert.Equal(t, tc.ExpectedHost, server)
			assert.Equal(t, tc.Type, transportType)
		})
	}
}

func TestMainRecAXFR(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"--all",
		"+recaxfr",
		"@nsztm1.digi.ninja", "zonetransfer.me",
	}, &out))
	assert.Contains(t, out.String(), `AXFR zonetransfer.me.`)
	assert.Contains(t, out.String(), `AXFR internal.zonetransfer.me.`)

	// Remove zonetransfer files
	files, err := filepath.Glob("zonetransfer.me*")
	assert.Nil(t, err)
	for _, f := range files {
		assert.Nil(t, os.RemoveAll(f))
	}
}

func TestMainShowAll(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"@9.9.9.9",
		"--all",
		"+all",
		"example.com",
		"A",
	}, &out))
	assert.Contains(t, out.String(), "example.com.")
	assert.Contains(t, out.String(), "Question:")
	assert.Contains(t, out.String(), "Answer:")
	assert.Contains(t, out.String(), "Stats:")
}

func TestMainResolveIPs(t *testing.T) {
	clearOpts()
	var out bytes.Buffer
	assert.Nil(t, driver([]string{
		"core1.fmt2.he.net",
		"A", "AAAA",
		"-R",
	}, &out))
	assert.Regexp(t, regexp.MustCompile(`core1.fmt2.he.net. .* A .* \(core1.fmt2.he.net.\)`), out.String())
}
