package output

import (
	"io"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
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
	Replies []*dns.Msg
	Server  string

	// Time is the total time it took to query this server
	Time time.Duration

	// Txp is the transport used to resolve IP addresses in A/AAAA records to their PTR records
	Txp *transport.Transport

	PTRs        map[string]string // IP -> PTR value
	existingRRs map[string]bool
}

// LoadPTRs populates an entry's PTRs map with PTR values for all A/AAAA records
func (e *Entry) LoadPTRs() {
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
			msg := dns.Msg{}
			msg.SetQuestion(qname, dns.TypePTR)

			// Resolve qname and cache result
			resp, err := (*e.Txp).Exchange(&msg)
			if err != nil {
				log.Debugf("error resolving PTR record: %s", err)
			}

			// Store in cache
			if len(resp.Answer) > 0 {
				e.PTRs[ip] = resp.Answer[0].(*dns.PTR).Ptr
			}
		}
	}
}
