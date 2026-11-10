package registry

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRIRServicesStayPaired(t *testing.T) {
	require.NotEmpty(t, rirServices)
	for name, svc := range rirServices {
		assert.NotEmpty(t, svc.rdapBase, name)
		assert.NotEmpty(t, svc.whoisHost, name)
		assert.Equal(t, svc.rdapBase, rirRDAPBase(name))
		assert.Equal(t, svc.whoisHost, rirWhoisHost(name))
	}

	assert.Empty(t, rirRDAPBase("iana"))
	assert.Empty(t, rirRDAPBase("nope"))
	assert.Equal(t, "whois.iana.org", rirWhoisHost("iana"))
	assert.Equal(t, "whois.iana.org", rirWhoisHost(""))
}

func TestParseWhoisReferral(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "ripe refer",
			body: "% comment\nrefer: whois.ripe.net\n",
			want: "whois.ripe.net",
		},
		{
			name: "whois server",
			body: "NetName: EXAMPLE\nWhois Server: whois.example.net\n",
			want: "whois.example.net",
		},
		{
			name: "arin referralserver",
			body: "ReferralServer: rwhois://rwhois.arin.net:4321/\n",
			want: "rwhois.arin.net:4321",
		},
		{
			name: "registrar whois server",
			body: "Registrar WHOIS Server: whois.godaddy.com\n",
			want: "whois.godaddy.com",
		},
		{
			name: "referral server scheme",
			body: "ReferralServer: rwhois://rwhois.example.com:4321/\n",
			want: "rwhois.example.com:4321",
		},
		{
			name: "referral server mixed case scheme",
			body: "ReferralServer: RWHOIS://rwhois.example.com:4321/\n",
			want: "rwhois.example.com:4321",
		},
		{
			name: "whois server mixed case scheme",
			body: "Whois Server: WHOIS://whois.example.net/\n",
			want: "whois.example.net",
		},
		{
			name: "earlier refer wins",
			body: "refer: whois.ripe.net\nWhois Server: whois.example.net\n",
			want: "whois.ripe.net",
		},
		{
			name: "commented whois server ignored",
			body: "% Whois Server: whois.hidden.example\n",
			want: "",
		},
		{
			name: "http registrar url ignored",
			body: "Registrar WHOIS Server: http://host\n",
			want: "",
		},
		{
			name: "http registrar url with port ignored",
			body: "Registrar WHOIS Server: http://host:4343\n",
			want: "",
		},
		{
			name: "https refer ignored",
			body: "refer: https://whois.example.net/path\n",
			want: "",
		},
		{
			name: "host port path trimmed",
			body: "Registrar WHOIS Server: whois.example.net:4343/path\n",
			want: "whois.example.net:4343",
		},
		{
			name: "refer with whois scheme",
			body: "refer: whois://whois.example.net/\n",
			want: "whois.example.net",
		},
		{
			name: "refer with mixed case scheme and port",
			body: "refer: WHOIS://whois.example.net:4343/foo\n",
			want: "whois.example.net:4343",
		},
		{
			name: "whois key with rwhois scheme",
			body: "whois: rwhois://rwhois.example.net:4321/\n",
			want: "rwhois.example.net:4321",
		},
		{
			name: "placeholder none ignored",
			body: "Whois Server: NONE\n",
			want: "",
		},
		{
			name: "invalid referral skipped for a later valid one",
			body: "Registrar WHOIS Server: http://host\nrefer: whois.example.net\n",
			want: "whois.example.net",
		},
		{
			name: "non numeric port ignored",
			body: "Whois Server: whois.example.net:http\n",
			want: "",
		},
		{
			name: "bare ipv6",
			body: "ReferralServer: 2001:db8::1\n",
			want: "2001:db8::1",
		},
		{
			name: "bracketed ipv6 with port",
			body: "ReferralServer: [2001:db8::1]:4321\n",
			want: "[2001:db8::1]:4321",
		},
		{
			name: "absolute fqdn",
			body: "refer: whois.example.net.\n",
			want: "whois.example.net.",
		},
		{
			name: "absolute fqdn with port",
			body: "Whois Server: whois.example.net.:4343\n",
			want: "whois.example.net.:4343",
		},
		{
			name: "repeated trailing dots ignored",
			body: "refer: whois.example.net..\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseWhoisReferral(tc.body))
		})
	}
}

func TestAppendEntityPublicIDStaysWithParent(t *testing.T) {
	parent := &rdap.Entity{
		Handle: "PARENT",
		Roles:  []string{"registrant"},
		PublicIDs: []rdap.PublicID{
			{Type: "IANA Registrar ID", Identifier: "1"},
		},
		Entities: []rdap.Entity{{
			Handle: "CHILD",
			Roles:  []string{"abuse"},
			PublicIDs: []rdap.PublicID{
				{Type: "IANA Registrar ID", Identifier: "2"},
			},
			Entities: []rdap.Entity{{
				Handle: "GRAND",
				Roles:  []string{"technical"},
			}},
		}},
	}

	var b kvBuilder
	appendEntity(&b, parent)
	got := b.String()

	want := strings.Join([]string{
		"Registrant: PARENT",
		"Public ID:  IANA Registrar ID=1",
		"",
		"Abuse:     CHILD",
		"Public ID: IANA Registrar ID=2",
		"",
		"Technical: GRAND",
	}, "\n")
	assert.Equal(t, want, got)
}

func TestFormatWhoisYAML(t *testing.T) {
	hops := []whoisHop{{Server: "whois.iana.org:43", Body: "domain: example.com\n"}}

	yamlOut, err := formatWhois(hops, "yaml")
	require.NoError(t, err)
	assert.Contains(t, yamlOut, "server: whois.iana.org:43")
	assert.Contains(t, yamlOut, "domain: example.com")
	assert.NotContains(t, yamlOut, ";; Server:")

	text, err := formatWhois(hops, "pretty")
	require.NoError(t, err)
	assert.Contains(t, text, ";; Server: whois.iana.org:43")
	assert.Contains(t, text, "domain: example.com")
}

func TestFormatRDAPYAML(t *testing.T) {
	// Wire JSON, not the openrdap struct. 4200000000 is an ASN-sized integer
	// that must stay in decimal form.
	body := []byte(`{"objectClassName":"domain","ldhName":"example.com","handle":"DOM-1","startAutnum":4200000000}`)
	resp := &rdap.Response{
		Object: &rdap.Domain{
			LDHName: "example.com",
			Handle:  "DOM-1",
		},
		HTTP: []*rdap.HTTPResponse{
			{Body: []byte(`{"ldhName":"earlier.example"}`)},
			{Body: body},
		},
	}

	yamlOut, err := formatRDAP(resp, "YAML")
	require.NoError(t, err)
	assert.Contains(t, yamlOut, "ldhName: example.com")
	assert.Contains(t, yamlOut, "objectClassName: domain")
	assert.Contains(t, yamlOut, "handle: DOM-1")
	assert.Contains(t, yamlOut, "startAutnum: 4200000000")
	assert.NotContains(t, yamlOut, "earlier.example")
	assert.NotContains(t, yamlOut, "ldhname:")
	assert.NotContains(t, yamlOut, "decodedata")
	assert.NotContains(t, yamlOut, "e+")
	assert.NotContains(t, yamlOut, "Domain Name:")

	ymlOut, err := formatRDAP(resp, "yml")
	require.NoError(t, err)
	assert.Equal(t, yamlOut, ymlOut)

	_, err = formatRDAP(&rdap.Response{Object: resp.Object}, "yaml")
	require.Error(t, err)

	pretty, err := formatRDAP(resp, "pretty")
	require.NoError(t, err)
	assert.Contains(t, pretty, "Domain Name: EXAMPLE.COM")

	js, err := formatRDAP(resp, "json")
	require.NoError(t, err)
	assert.Contains(t, js, `"LDHName": "example.com"`)
}

func TestFormatWhoisYAMLNormalizesBody(t *testing.T) {
	hops := []whoisHop{{
		Server: "whois.iana.org:43",
		Body:   "domain: example.com  \r\nregistrar: Example\t\r\n",
	}}

	yamlOut, err := formatWhois(hops, "yaml")
	require.NoError(t, err)
	assert.Contains(t, yamlOut, "body: |")
	assert.Contains(t, yamlOut, "domain: example.com\n")
	assert.Contains(t, yamlOut, "registrar: Example\n")
	assert.NotContains(t, yamlOut, "\\r")
	assert.NotContains(t, yamlOut, "body: \"")

	// Text keeps the CR and trailing space that YAML strips.
	text, err := formatWhois(hops, "pretty")
	require.NoError(t, err)
	assert.Contains(t, text, "domain: example.com  \r\n")

	bad := []whoisHop{{
		Server: "whois.iana.org:43",
		Body:   "ok\n" + string([]byte{0xff, 0xfe}),
	}}
	yamlOut, err = formatWhois(bad, "yaml")
	require.NoError(t, err)
	assert.NotContains(t, yamlOut, "!!binary")
	assert.Contains(t, yamlOut, "\uFFFD")

	js, err := formatWhois(bad, "json")
	require.NoError(t, err)
	assert.NotContains(t, js, string([]byte{0xff}))
	assert.Contains(t, js, "\uFFFD")
}

func TestWithDefaultPort(t *testing.T) {
	assert.Equal(t, "", withDefaultPort("", "43"))
	assert.Equal(t, "whois.example.net:43", withDefaultPort("whois.example.net", "43"))
	assert.Equal(t, "whois.example.net:4343", withDefaultPort("whois.example.net:4343", "43"))
	assert.Equal(t, "127.0.0.1:43", withDefaultPort("127.0.0.1:43", "43"))
	assert.Equal(t, "[2001:db8::1]:43", withDefaultPort("2001:db8::1", "43"))
}

func TestWhoisEndpointKey(t *testing.T) {
	assert.Equal(t, whoisEndpointKey("whois.example.net"), whoisEndpointKey("whois.example.net."))
	assert.Equal(t, whoisEndpointKey("whois.example.net"), whoisEndpointKey("WHOIS.example.net:43"))
	assert.Equal(t, whoisEndpointKey("2001:db8::1"), whoisEndpointKey("[2001:db8::1]:43"))
	assert.Equal(t, whoisEndpointKey("2001:db8::1"), whoisEndpointKey("2001:db8:0:0:0:0:0:1"))
	assert.NotEqual(t, whoisEndpointKey("whois.example.net:43"), whoisEndpointKey("whois.example.net:4321"))
}

func TestWhoisChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	second := listenWhois(t, "domain: example.com\r\n")
	// Scheme and path must be stripped before the second hop is dialed.
	first := listenWhois(t, "refer: whois://"+second+"/path\r\n")

	hops, err := whoisChain(ctx, "example.com", first, time.Second)
	require.NoError(t, err)
	require.Len(t, hops, 2)
	assert.Equal(t, first, hops[0].Server)
	assert.Equal(t, second, hops[1].Server)
	assert.Contains(t, hops[1].Body, "domain: example.com")

	// Invalid referrals are not dialed, so the chain stops after one hop.
	bad := listenWhois(t, "Registrar WHOIS Server: http://host\r\nWhois Server: NONE\r\nrefer: whois://host/\r\n")
	hops, err = whoisChain(ctx, "example.com", bad, time.Second)
	require.NoError(t, err)
	require.Len(t, hops, 1)
	assert.NotContains(t, hops[0].Body, ";; error:")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := ln.Addr().String()
	require.NoError(t, ln.Close())

	referring := listenWhois(t, "refer: "+closed+"\n")
	hops, err = whoisChain(ctx, "example.com", referring, time.Second)
	require.NoError(t, err)
	require.Len(t, hops, 2)
	assert.Contains(t, hops[1].Body, ";; error:")

	hops, err = whoisChain(ctx, "example.com", closed, time.Second)
	require.Error(t, err)
	assert.Empty(t, hops)

	// [127.0.0.1]:port and 127.0.0.1:port are one endpoint. A self-referral
	// in the other spelling must not open a second connection.
	self, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = self.Close() })
	plain := self.Addr().String()
	bracketed := fmt.Sprintf("[127.0.0.1]:%d", self.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			conn, accErr := self.Accept()
			if accErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("refer: " + plain + "\n"))
			}(conn)
		}
	}()
	hops, err = whoisChain(ctx, "example.com", bracketed, time.Second)
	require.NoError(t, err)
	require.Len(t, hops, 1)
	assert.Equal(t, bracketed, hops[0].Server)
}

func TestQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Query(ctx, Options{})
	require.Error(t, err)
	_, err = Query(ctx, Options{Target: "example.com"})
	require.Error(t, err)

	addr := listenWhois(t, "domain: example.com  \r\n")
	out, err := Query(ctx, Options{
		Target:      "example.com",
		UseWHOIS:    true,
		WhoisServer: addr,
		RIR:         "IANA",
		Format:      "yml",
		Timeout:     time.Second,
	})
	require.NoError(t, err)
	assert.Contains(t, out, "server: "+addr)
	assert.Contains(t, out, "body: |")
	assert.Contains(t, out, "domain: example.com\n")
	assert.NotContains(t, out, "\\r")
}

func listenWhois(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()
	return ln.Addr().String()
}
