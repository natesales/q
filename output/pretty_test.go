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

func TestDedupeAnswersByContentKeepsLongestTTL(t *testing.T) {
	rr1, err := dns.NewRR("www.example.com. 60 IN CNAME example.com.")
	assert.NoError(t, err)
	rr2, err := dns.NewRR("www.example.com. 3600 IN CNAME example.com.")
	assert.NoError(t, err)
	rr3, err := dns.NewRR("www.example.com. 120 IN CNAME example.com.")
	assert.NoError(t, err)
	rrA, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	assert.NoError(t, err)

	out := dedupeAnswersByContent([]dns.RR{rr1, rrA, rr2, rr3})
	assert.Len(t, out, 2)
	assert.Equal(t, uint32(3600), out[0].Header().Ttl)
	assert.Equal(t, dns.TypeCNAME, out[0].Header().Rrtype)
	assert.Equal(t, uint32(300), out[1].Header().Ttl)
	assert.Equal(t, dns.TypeA, out[1].Header().Rrtype)
}

func TestPrintPrettyDedupesCNAMEAcrossReplies(t *testing.T) {
	var buf bytes.Buffer
	util.UseColor = false
	cnameLow, err := dns.NewRR("www.example.com. 60 IN CNAME example.com.")
	assert.NoError(t, err)
	cnameHigh, err := dns.NewRR("www.example.com. 7200 IN CNAME example.com.")
	assert.NoError(t, err)
	a, err := dns.NewRR("example.com. 300 IN A 192.0.2.9")
	assert.NoError(t, err)

	entries := []*Entry{{
		Replies: []*dns.Msg{
			{Answer: []dns.RR{cnameLow}},
			{Answer: []dns.RR{cnameHigh, a}},
			{Answer: []dns.RR{cnameLow}},
		},
		Server: "192.0.2.10",
	}}
	p := Printer{Out: &buf, Opts: &cli.Flags{Format: "pretty", ShowAnswer: true, PrettyTTLs: true, ShortTTLs: true}}
	p.PrintPretty(entries)
	got := buf.String()
	assert.Equal(t, 1, strings.Count(got, "CNAME"))
	assert.Contains(t, got, "2h")
	assert.Contains(t, got, "A")
	assert.NotContains(t, got, "1m0s")
}
