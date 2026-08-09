package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/natesales/q/transport"

	"github.com/charmbracelet/log"
	"github.com/miekg/dns"

	"github.com/natesales/q/cli"
)

var (
	FormatPretty = "pretty"
	FormatColumn = "column"
	FormatJSON   = "json"
	FormatYAML   = "yaml"
	FormatRAW    = "raw"
)

// Printer stores global options across multiple entries
type Printer struct {
	Out  io.Writer
	Opts *cli.Flags

	// Longest string lengths for column formatting
	longestTTL    int
	longestRRType int
}

// Entry stores the replies from a server
type Entry struct {
	Queries []dns.Msg
	Replies []*dns.Msg
	Server  string

	// Time is the total time it took to query this server
	Time time.Duration

	PTRs        map[string]string `json:"-"` // IP -> PTR value
	existingRRs map[string]bool
}

// maxPTRChase bounds CNAME chasing when resolving a PTR record. 16 matches
// BIND's CNAME-chase limit.
const maxPTRChase = 16

// resolvePTR queries qname for a PTR record, following any CNAME chain
// until a PTR record is found; see RFC 2317 (Classless IN-ADDR.ARPA delegation). It
// returns an empty string if no PTR record is ultimately found, and an
// error if the chain contains a loop or is too long.
func (e *Entry) resolvePTR(txp *transport.Transport, qname string) (string, error) {
	origQname := qname
	// Map for loop checking
	visited := make(map[string]bool)

	// Loop for one initial query plus n=maxPTRChase follow-up queries
	for i := 0; i <= maxPTRChase; i++ {
		if visited[strings.ToLower(qname)] {
			return "", fmt.Errorf("CNAME loop detected resolving PTR for %s", origQname)
		}
		visited[strings.ToLower(qname)] = true

		msg := dns.Msg{}
		msg.SetQuestion(qname, dns.TypePTR)

		resp, err := (*txp).Exchange(&msg)
		if err != nil {
			return "", err
		}
		if resp == nil {
			return "", nil
		}

		var next string
		for _, rr := range resp.Answer {
			switch rr.Header().Rrtype {
			case dns.TypePTR:
				return rr.(*dns.PTR).Ptr, nil
			case dns.TypeCNAME:
				next = rr.(*dns.CNAME).Target
			}
		}

		if next == "" {
			return "", nil
		}
		qname = next
	}
	return "", fmt.Errorf("CNAME chain too long resolving PTR for %s", origQname)
}

// LoadPTRs populates an entry's PTRs map with PTR values for all A/AAAA records
func (e *Entry) LoadPTRs(txp *transport.Transport) {
	// Initialize PTR cache if it doesn't exist
	if e.PTRs == nil {
		e.PTRs = make(map[string]string)
	}

	for _, reply := range e.Replies {
		for _, rr := range reply.Answer {
			var ip string

			switch rr.Header().Rrtype {
			case dns.TypeA:
				ip = rr.(*dns.A).A.String()
			case dns.TypeAAAA:
				ip = rr.(*dns.AAAA).AAAA.String()
			default:
				continue
			}

			// Create PTR query
			qname, err := dns.ReverseAddr(ip)
			if err != nil {
				log.Fatalf("error reversing PTR record: %s", err)
			}

			// Resolve qname (following CNAMEs) and cache result
			ptr, err := e.resolvePTR(txp, qname)
			if err != nil {
				log.Warnf("error resolving PTR record: %s", err)
				continue
			}
			if ptr != "" {
				e.PTRs[ip] = ptr
			}
		}
	}
}
