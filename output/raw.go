package output

import (
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/natesales/q/util"
)

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
			if p.Opts.ShowAnswer && len(reply.Answer) > 0 {
				s += "\n;; ANSWER SECTION:\n"
				for _, r := range reply.Answer {
					if r != nil {
						s += r.String() + "\n"
					}
				}
			}
			if p.Opts.ShowAuthority && len(reply.Ns) > 0 {
				s += "\n;; AUTHORITY SECTION:\n"
				for _, r := range reply.Ns {
					if r != nil {
						s += r.String() + "\n"
					}
				}
			}
			if p.Opts.ShowAdditional && len(reply.Extra) > 0 && (opt == nil || len(reply.Extra) > 1) {
				s += "\n;; ADDITIONAL SECTION:\n"
				for _, r := range reply.Extra {
					if r != nil && r.Header().Rrtype != dns.TypeOPT {
						s += r.String() + "\n"
					}
				}
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
