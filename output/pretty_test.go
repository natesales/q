package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/util"
)

func TestOutputPrettyPrintColumn(t *testing.T) {
	var buf bytes.Buffer
	util.UseColor = false
	p := Printer{Out: &buf, Opts: &cli.Flags{Format: "column"}}
	p.PrintColumn(entries)
	assert.Contains(t, buf.String(), `A 86400 192.0.2.2`)
	assert.Contains(t, buf.String(), `MX 86400 0 .`)
	assert.Contains(t, buf.String(), `NS 86400 a.iana-servers.net.`)
	assert.Contains(t, buf.String(), `NS 86400 b.iana-servers.net.`)
	assert.Contains(t, buf.String(), `TXT 86400 "v=spf1 -all"`)
}

func TestRRToRFC3597Val(t *testing.T) {
	// A record: RDATA is 4 bytes IPv4 address
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 1},
	}
	val := rrToRFC3597Val(rr)
	assert.True(t, strings.HasPrefix(val, `\# 4 `), "expected RFC 3597 prefix '\\# 4 ', got: %s", val)
	assert.Contains(t, val, "c0000201") // 192.0.2.1 in hex
}

func TestUnknownFormatOutput(t *testing.T) {
	util.UseColor = false
	entry := &Entry{
		Replies: []*dns.Msg{
			{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   []byte{192, 0, 2, 1},
					},
				},
			},
		},
	}
	var buf bytes.Buffer
	p := Printer{Out: &buf, Opts: &cli.Flags{ShowAnswer: true, UnknownFormat: true, PrettyTTLs: false}}
	p.PrintPretty([]*Entry{entry})
	out := buf.String()
	assert.Contains(t, out, `\# 4 `)
	assert.Contains(t, out, "c0000201")
	assert.Contains(t, out, "TYPE1")
	assert.NotContains(t, out, " A ")
}
