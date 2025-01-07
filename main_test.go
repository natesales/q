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

func run(args ...string) (*bytes.Buffer, error) {
	clearOpts()
	var out bytes.Buffer
	err := driver(append([]string{"+nocolor"}, args...), &out)
	return &out, err
}

func TestMainQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* TXT "v=spf1 -all"`), out.String())
}

func TestMainVersion(t *testing.T) {
	out, err := run("-V")
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "https://github.com/natesales/q version dev (unknown unknown)")
}

// TODO
//func TestMainODoHQuery(t *testing.T) {
//	out, err := run(
//		"--all",
//		"-q", "example.com",
//		"-s", "https://odoh.cloudflare-dns.com",
//		"--odoh-proxy", "https://odoh.crypto.sx",
//	)
//	assert.Nil(t, err)
//	assert.Regexp(t, regexp.MustCompile(`example.com. .* TXT "v=spf1 -all"`), out.String())
//}

func TestMainRawFormat(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--format=raw",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "v=spf1 -all")
	assert.Contains(t, out.String(), "a.iana-servers.net")
}

func TestMainJSONFormat(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--format=json",
	)
	assert.Nil(t, err)
	o := strings.ReplaceAll(out.String(), `\\"`, `"`)
	assert.Contains(t, o, `"preference":0,"mx":"."`)
	assert.Contains(t, o, `"ns":"a.iana-servers.net."`)
	assert.Contains(t, o, `"txt":["v=spf1 -all"`)
}

func TestMainInvalidOutputFormat(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"--format=invalid",
	)
	if !(err != nil && strings.Contains(err.Error(), "invalid output format")) {
		t.Errorf("invalid output format should throw an error")
	}
}

func TestMainParseTypes(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"-t", "AAAA",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
	assert.Regexp(t, regexp.MustCompile(`example.com. .* AAAA .*`), out.String())
}

func TestMainInvalidTypes(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-t", "INVALID",
	)
	if !(err != nil && strings.Contains(err.Error(), "INVALID is not a valid RR type")) {
		t.Errorf("expected invalid type error, got %+v", err)
	}
}

func TestMainInvalidODoHUpstream(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-s", "tls://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh.crypto.sx",
	)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH target must use HTTPS")
}

func TestMainInvalidODoHProxy(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "tls://odoh1.surfdomeinen.nl",
	)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH proxy must use HTTPS")
}

func TestMainReverseQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-x",
		"-q", "1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`1.1.1.1.in-addr.arpa. .* PTR one.one.one.one`), out.String())
}

func TestMainInferredQname(t *testing.T) {
	out, err := run(
		"--all",
		"example.com",
		"A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInferredServer(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@8.8.8.8",
		"-t", "A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidReverseQuery(t *testing.T) {
	_, err := run(
		"--all",
		"-x",
		"example.com",
	)
	if !(err != nil && strings.Contains(err.Error(), "unrecognized address: example.com")) {
		t.Errorf("expected address error, got %+v", err)
	}
}

func TestMainInvalidUpstream(t *testing.T) {
	_, err := run(
		"--all",
		"-s", "127.127.127.127:1",
		"example.com",
	)
	if !(err != nil &&
		(strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "i/o timeout"))) {
		t.Errorf("expected connection error, got %+v", err)
	}
}

func TestMainDNSSECArg(t *testing.T) {
	out, err := run(
		"--all",
		"example.com",
		"+dnssec",
		"@9.9.9.9",
	)
	assert.Nil(t, err)
	t.Logf("out: %s", out.String())
	assert.Regexp(t, regexp.MustCompile(`example.com. .* RRSIG .*`), out.String())
}

func TestMainPad(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--pad",
		"--format=json",
	)
	assert.Nil(t, err)
	o := strings.ReplaceAll(out.String(), `\\"`, `"`)
	assert.Contains(t, o, `"truncated":false`)
}

func TestMainChaosClass(t *testing.T) {
	out, err := run(
		"--all",
		"id.server",
		"CH",
		"TXT",
		"@9.9.9.9",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`id.server. .* TXT ".*.pch.net"`), out.String())
}

func TestMainParsePlusFlags(t *testing.T) {
	cli.ParsePlusFlags(&opts, []string{"+dnssec", "+nord"})
	assert.True(t, opts.DNSSEC)
	assert.False(t, opts.RecursionDesired)
}

func TestMainTCPQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-t", "A",
		"-q", "example.com",
		"@tcp://1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLSQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@tls://1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainHTTPSQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@https://dns.quad9.net",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainQUICQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@quic://dns.adguard.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptStampQuery(t *testing.T) {
	out, err := run(
		"-q", "example.com",
		"-t", "A",
		"@sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptManualQuery(t *testing.T) {
	out, err := run(
		"-q", "example.com",
		"-t", "A",
		"@dnscrypt://94.140.14.14:5443",
		"--dnscrypt-key", "d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873",
		"--dnscrypt-provider", "2.dnscrypt.default.ns1.adguard.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidServerURL(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@bad::server::url",
		"--format=json",
	)
	assert.NotNil(t, err)
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidTransportScheme(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@invalid://example.com",
		"--format=json",
	)
	assert.NotNil(t, err)
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLS12(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--tls-min-version=1.1",
		"--tls-max-version=1.2",
		"@tls://dns.quad9.net",
		"-t", "A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainNSID(t *testing.T) {
	out, err := run(
		"--all",
		"@9.9.9.9",
		"+nsid",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`.*.pch.net.*`), out.String())
}

func TestMainECSv4(t *testing.T) {
	out, err := run(
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "192.0.2.0/24",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), `'subnet':'192.0.2.0/24/0'`)
}

func TestMainECSv6(t *testing.T) {
	out, err := run(
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "2001:db8::/48",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), `'subnet':'[2001:db8::]/48/0'`)
}

func TestMainHTTPUserAgent(t *testing.T) {
	out, err := run(
		"--all",
		"@https://dns.quad9.net",
		"--http-user-agent", "Example/1.0",
		"-t", "NS",
	)
	assert.Nil(t, err)
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
		{ // IPv6 plain with scope ID but without port
			Server:       "fe80::1%en0",
			Type:         transport.TypePlain,
			ExpectedHost: "[fe80::1%en0]:53",
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
	out, err := run(
		"--all",
		"+recaxfr",
		"@nsztm1.digi.ninja", "zonetransfer.me",
	)
	assert.Nil(t, err)
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
	out, err := run(
		"@9.9.9.9",
		"--all",
		"+all",
		"example.com",
		"A",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "example.com.")
	assert.Contains(t, out.String(), "Question:")
	assert.Contains(t, out.String(), "Answer:")
	assert.Contains(t, out.String(), "Stats:")
}

func TestMainResolveIPs(t *testing.T) {
	out, err := run(
		"core1.fmt2.he.net",
		"A", "AAAA",
		"-R",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`core1.fmt2.he.net. .* A .* \(core1.fmt2.he.net.\)`), out.String())
}

func TestMainQueryDomainWithRRType(t *testing.T) {
	out, err := run(
		"NS.network",
		"A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`NS.network. .* A .*`), out.String())
}

func TestMainQueryTypeFlag(t *testing.T) {
	out, err := run(
		"-t", "65",
		"cloudflare.com",
		"-v",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`cloudflare.com. .* HTTPS 1 .*`), out.String())
}

func TestMainDnsstampDoH(t *testing.T) {
	out, err := run(
		"@sdns://AgcAAAAAAAAADjEwNC4xNi4yNDguMjQ5ABJjbG91ZGZsYXJlLWRucy5jb20A", // cloudflare-dns.com
		"--all",
	)

	assert.Nil(t, err)
	assert.Contains(t, out.String(), "from https://cloudflare-dns.com:443/dns-query")
}

func TestMainDnsstampDoHPath(t *testing.T) {
	_, err := run(
		"@sdns://AgcAAAAAAAAADjEwNC4xNi4yNDguMjQ5ABJjbG91ZGZsYXJlLWRucy5jb20FL3Rlc3Q", // cloudflare-dns.com/test
		"--all",
	)

	// use err here because the query will result in a 404
	assert.Contains(t, err.Error(), "from https://cloudflare-dns.com:443/test")
}

