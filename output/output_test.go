package output

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/natesales/q/transport"
)

// replies returns a slice of example DNS answer messages
func replies() []*dns.Msg {
	testZone := `
example.com. 86400 IN A 192.0.2.1
example.com. 86400 IN A 192.0.2.2
example.com. 86400 IN NS b.iana-servers.net.
example.com. 86400 IN NS a.iana-servers.net.
example.com. 86400 IN MX 0 .
example.com. 86400 IN TXT "v=spf1 -all"
`

	// Convert the zone to DNS messages
	var msgs []*dns.Msg
	for _, line := range strings.Split(testZone, "\n") {
		if line != "" {
			rr, err := dns.NewRR(line)
			if err != nil {
				panic(err)
			}
			msgs = append(msgs, &dns.Msg{Answer: []dns.RR{rr}})
		}
	}

	return msgs
}

var entries = []*Entry{
	{
		Replies:     replies(),
		Server:      "192.0.2.10",
		Time:        time.Second * 2,
		PTRs:        nil,
		existingRRs: nil,
	},
}

// scriptedTransport returns a canned dns.Msg for each successive Exchange call.
type scriptedTransport struct {
	responses []*dns.Msg
	calls     int
}

func (t *scriptedTransport) Exchange(_ *dns.Msg) (*dns.Msg, error) {
	resp := t.responses[t.calls]
	t.calls++
	return resp, nil
}

func (t *scriptedTransport) Close() error { return nil }

func msgWithRRs(rrs ...string) *dns.Msg {
	m := &dns.Msg{}
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

func TestLoadPTRs(t *testing.T) {
	cases := []struct {
		name      string
		responses []*dns.Msg
		wantPTR   string
	}{
		{
			name: "direct PTR",
			responses: []*dns.Msg{
				msgWithRRs(`1.2.0.192.in-addr.arpa. 3600 IN PTR host1.example.`),
			},
			wantPTR: "host1.example.",
		},
		{
			name: "CNAME followed by PTR in the same answer (RFC 2317, server-side chase)",
			responses: []*dns.Msg{
				msgWithRRs(
					`1.2.0.192.in-addr.arpa. 3600 IN CNAME 1.0/25.2.0.192.in-addr.arpa.`,
					`1.0/25.2.0.192.in-addr.arpa. 3600 IN PTR host1.example.`,
				),
			},
			wantPTR: "host1.example.",
		},
		{
			name: "bare CNAME requiring client-side follow-up query (RFC 2317)",
			responses: []*dns.Msg{
				msgWithRRs(`1.2.0.192.in-addr.arpa. 3600 IN CNAME 1.0/25.2.0.192.in-addr.arpa.`),
				msgWithRRs(`1.0/25.2.0.192.in-addr.arpa. 3600 IN PTR host1.example.`),
			},
			wantPTR: "host1.example.",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &Entry{
				Replies: []*dns.Msg{msgWithRRs(`example.com. 3600 IN A 192.0.2.1`)},
			}
			var txp transport.Transport = &scriptedTransport{responses: c.responses}

			e.LoadPTRs(&txp)

			if got := e.PTRs["192.0.2.1"]; got != c.wantPTR {
				t.Errorf("PTRs[192.0.2.1] = %q, want %q", got, c.wantPTR)
			}
		})
	}
}
