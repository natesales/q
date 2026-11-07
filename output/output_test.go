package output

import (
	"fmt"
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

// scriptedTransport returns a canned dns.Msg for each successive Exchange
// call, in order. It fails the test clearly (rather than panicking with an
// opaque index-out-of-range) if more Exchange calls happen than scripted,
// and records the queried names so callers can assert on them.
type scriptedTransport struct {
	t         *testing.T
	responses []*dns.Msg
	calls     int
	queried   []string
}

func (st *scriptedTransport) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if st.calls >= len(st.responses) {
		st.t.Fatalf("unexpected Exchange call #%d for query %q; only %d response(s) scripted", st.calls+1, msg.Question[0].Name, len(st.responses))
	}
	st.queried = append(st.queried, msg.Question[0].Name)
	resp := st.responses[st.calls]
	st.calls++
	return resp, nil
}

func (st *scriptedTransport) Close() error { return nil }

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
			var txp transport.Transport = &scriptedTransport{t: t, responses: c.responses}

			e.LoadPTRs(&txp)

			if got := e.PTRs["192.0.2.1"]; got != c.wantPTR {
				t.Errorf("PTRs[192.0.2.1] = %q, want %q", got, c.wantPTR)
			}
		})
	}
}

// chainOfCNAMEs returns n CNAME responses linking names[0]->names[1]->...->names[n],
// plus a final PTR response for names[n], so callers can script an exact chain length.
func chainOfCNAMEs(n int, target string) (names []string, responses []*dns.Msg) {
	names = make([]string, n+1)
	names[0] = "1.2.0.192.in-addr.arpa."
	for i := 1; i <= n; i++ {
		names[i] = fmt.Sprintf("step%d.example.", i)
	}
	for i := 0; i < n; i++ {
		responses = append(responses, msgWithRRs(fmt.Sprintf(`%s 3600 IN CNAME %s`, names[i], names[i+1])))
	}
	responses = append(responses, msgWithRRs(fmt.Sprintf(`%s 3600 IN PTR %s`, names[n], target)))
	return names, responses
}

func TestResolvePTRAllowsFullChaseLength(t *testing.T) {
	// A chain of exactly maxPTRChase CNAMEs before the terminal PTR must
	// succeed: resolvePTR should allow one initial query plus maxPTRChase
	// follow-ups, not maxPTRChase total queries.
	names, responses := chainOfCNAMEs(maxPTRChase, "host.example.")

	e := &Entry{}
	var txp transport.Transport = &scriptedTransport{t: t, responses: responses}

	ptr, err := e.resolvePTR(&txp, names[0])
	if err != nil {
		t.Fatalf("resolvePTR returned unexpected error: %v", err)
	}
	if ptr != "host.example." {
		t.Errorf("resolvePTR = %q, want %q", ptr, "host.example.")
	}
}

func TestResolvePTRChainTooLongReportsOriginalName(t *testing.T) {
	// One more CNAME hop than resolvePTR allows: it must give up, and the
	// error must name the original query, not the last CNAME target chased.
	names, responses := chainOfCNAMEs(maxPTRChase+1, "host.example.")

	e := &Entry{}
	var txp transport.Transport = &scriptedTransport{t: t, responses: responses}

	_, err := e.resolvePTR(&txp, names[0])
	if err == nil {
		t.Fatal("resolvePTR returned nil error for an over-long CNAME chain")
	}
	if !strings.Contains(err.Error(), names[0]) {
		t.Errorf("error %q does not mention the original qname %q", err.Error(), names[0])
	}
	if strings.Contains(err.Error(), names[len(names)-1]) {
		t.Errorf("error %q mentions the last chased CNAME target instead of the original qname", err.Error())
	}
}

func TestResolvePTRDetectsCNAMELoop(t *testing.T) {
	origName := "1.2.0.192.in-addr.arpa."
	other := "loop.example."

	// origName -> other -> origName -> ... : should be caught as soon as a
	// name repeats, without exhausting the full maxPTRChase budget.
	responses := []*dns.Msg{
		msgWithRRs(fmt.Sprintf(`%s 3600 IN CNAME %s`, origName, other)),
		msgWithRRs(fmt.Sprintf(`%s 3600 IN CNAME %s`, other, origName)),
	}

	e := &Entry{}
	st := &scriptedTransport{t: t, responses: responses}
	var txp transport.Transport = st

	_, err := e.resolvePTR(&txp, origName)
	if err == nil {
		t.Fatal("resolvePTR returned nil error for a CNAME loop")
	}
	if st.calls != 2 {
		t.Errorf("resolvePTR made %d Exchange call(s), want exactly 2 (loop should be detected as soon as a name repeats, not after exhausting maxPTRChase)", st.calls)
	}
}
