package output

import (
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/natesales/q/util"
)

// rrSection generates a printable section from a given RR slice
func rrSection(s, label string, rrs []dns.RR) string {
	if len(rrs) > 0 {
		s += "\n;; " + label + " SECTION:\n"
		for _, r := range rrs {
			if r != nil {
				s += r.String() + "\n"
			}
		}
	}

	return s
}

// PrintRaw a slice of entries in raw (dig-style) format
func (p Printer) PrintRaw(entries []*Entry) {
	for _, entry := range entries {
		for i, reply := range entry.Replies {
			s := reply.MsgHdr.String() + " "
			s += "QUERY: " + strconv.Itoa(len(reply.Question)) + ", "
			s += "ANSWER: " + strconv.Itoa(len(reply.Answer)) + ", "
			s += "AUTHORITY: " + strconv.Itoa(len(reply.Ns)) + ", "
			s += "ADDITIONAL: " + strconv.Itoa(len(reply.Extra)) + "\n"
			opt := reply.IsEdns0()
			if opt != nil {
				// OPT PSEUDOSECTION
				s += opt.String() + "\n"
			}
			if p.Opts.ShowQuestion && len(reply.Question) > 0 {
				s += "\n;; QUESTION SECTION:\n"
				for _, r := range reply.Question {
					s += r.String() + "\n"
				}
			}
			if p.Opts.ShowAnswer {
				s += rrSection(s, "ANSWER", reply.Answer)
			}
			if p.Opts.ShowAuthority {
				s += rrSection(s, "AUTHORITY", reply.Ns)
			}
			if p.Opts.ShowAdditional && (opt == nil || len(reply.Extra) > 1) {
				s += rrSection(s, "ADDITIONAL", reply.Extra)
			}
			util.MustWriteln(p.Out, s)

			if p.Opts.ShowStats {
				util.MustWritef(p.Out, ";; Received %d B\n", reply.Len())
				util.MustWritef(p.Out, ";; Time %s\n", time.Now().Format("15:04:05 01-02-2006 MST"))
				util.MustWritef(p.Out, ";; From %s in %s\n", entry.Server, entry.Time.Round(100*time.Microsecond))
			}

			// Print separator if there is more than one query
			if len(entry.Replies) > 0 && i != len(entry.Replies)-1 {
				util.MustWritef(p.Out, "\n--\n\n")
			}
		}
	}
}
