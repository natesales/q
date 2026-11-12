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

func TestPrettyNXDOMAIN(t *testing.T) {
	oldColor := util.UseColor
	util.UseColor = false
	t.Cleanup(func() { util.UseColor = oldColor })

	for _, tt := range []struct {
		name      string
		rcode     int
		valueOnly bool
		showStats bool
		question  bool
		query     bool
		servers   []string
		want      string
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError, question: true, want: "missing.example. NXDOMAIN\n"},
		{name: "single configured server", rcode: dns.RcodeNameError, question: true, servers: []string{"192.0.2.53:53"}, want: "missing.example. NXDOMAIN\n"},
		{name: "only one configured server responds", rcode: dns.RcodeNameError, question: true, servers: []string{"192.0.2.53:53", "192.0.2.54:53"}, want: "missing.example. NXDOMAIN (192.0.2.53:53)\n"},
		{name: "empty NOERROR", rcode: dns.RcodeSuccess, question: true},
		{name: "SERVFAIL is not NXDOMAIN", rcode: dns.RcodeServerFailure, question: true},
		{name: "REFUSED is not NXDOMAIN", rcode: dns.RcodeRefused, question: true},
		{name: "short output", rcode: dns.RcodeNameError, question: true, valueOnly: true},
		{name: "stats already show status", rcode: dns.RcodeNameError, question: true, showStats: true},
		{name: "use original question", rcode: dns.RcodeNameError, query: true, want: "missing.example. NXDOMAIN\n"},
		{name: "no question available", rcode: dns.RcodeNameError, want: "Status: NXDOMAIN\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			query := dns.Msg{}
			query.SetQuestion("missing.example.", dns.TypeA)
			reply := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: tt.rcode}}
			if tt.question {
				reply.Question = query.Question
			}
			entry := &Entry{Replies: []*dns.Msg{reply}, Server: "192.0.2.53:53"}
			if tt.query {
				entry.Queries = []dns.Msg{query}
			}
			var buf bytes.Buffer
			p := Printer{Out: &buf, Opts: &cli.Flags{ShowAnswer: true, ValueOnly: tt.valueOnly, ShowStats: tt.showStats, Server: tt.servers}}
			p.PrintPretty([]*Entry{entry})
			if tt.showStats {
				assert.Contains(t, buf.String(), "Status: NXDOMAIN")
				assert.Equal(t, 1, strings.Count(buf.String(), "NXDOMAIN"))
			} else {
				assert.Equal(t, tt.want, buf.String())
			}
		})
	}
}

func TestPrettyNXDOMAINDeduplication(t *testing.T) {
	oldColor := util.UseColor
	util.UseColor = false
	t.Cleanup(func() { util.UseColor = oldColor })

	response := func(name string, typ uint16) *dns.Msg {
		query := &dns.Msg{}
		query.SetQuestion(name, typ)
		return new(dns.Msg).SetRcode(query, dns.RcodeNameError)
	}
	replies := []*dns.Msg{
		response("missing.example.", dns.TypeA),
		response("MISSING.example.", dns.TypeAAAA),
		response("other.example.", dns.TypeMX),
	}
	var buf bytes.Buffer
	p := Printer{Out: &buf, Opts: &cli.Flags{ShowAnswer: true}}
	p.PrintPretty([]*Entry{
		{Replies: replies, Server: "192.0.2.53:53"},
		{Replies: replies, Server: "192.0.2.54:53"},
	})
	assert.Equal(t, "missing.example. NXDOMAIN (192.0.2.53:53)\nother.example. NXDOMAIN (192.0.2.53:53)\nmissing.example. NXDOMAIN (192.0.2.54:53)\nother.example. NXDOMAIN (192.0.2.54:53)\n", buf.String())
}

func TestPrettyNXDOMAINWithCNAME(t *testing.T) {
	oldColor := util.UseColor
	util.UseColor = false
	t.Cleanup(func() { util.UseColor = oldColor })

	query := &dns.Msg{}
	query.SetQuestion("alias.example.", dns.TypeA)
	reply := new(dns.Msg).SetRcode(query, dns.RcodeNameError)
	reply.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "missing.example.",
	}}
	var buf bytes.Buffer
	p := Printer{Out: &buf, Opts: &cli.Flags{ShowAnswer: true}}
	p.PrintPretty([]*Entry{{Replies: []*dns.Msg{reply}}})
	assert.Equal(t, "alias.example. NXDOMAIN\nalias.example. 300 CNAME missing.example.\n", buf.String())
}

func TestPrettyNXDOMAINColor(t *testing.T) {
	oldColor := util.UseColor
	util.UseColor = true
	t.Cleanup(func() { util.UseColor = oldColor })

	var buf bytes.Buffer
	p := Printer{Out: &buf, Opts: &cli.Flags{ShowAnswer: true}}
	p.PrintPretty([]*Entry{{Replies: []*dns.Msg{{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}}}})
	assert.Contains(t, buf.String(), "\x1b[1;31mNXDOMAIN\x1b[0m")
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
