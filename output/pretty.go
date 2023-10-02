package output

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
	whois "github.com/natesales/bgptools-go"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/util"
)

func PrettyPrintNSID(opt []*dns.Msg, out io.Writer) {
	for _, r := range opt {
		for _, o := range r.Extra {
			if o.Header().Rrtype == dns.TypeOPT {
				opt := o.(*dns.OPT)
				for _, e := range opt.Option {
					if e.Option() == dns.EDNS0NSID {
						nsidStr, err := hex.DecodeString(e.String())
						if err != nil {
							log.Warnf("error decoding NSID: %s", err)
							return
						}
						util.MustWritef(out, "%s %s\n",
							util.Color("white", "NSID:"),
							util.Color("purple", string(nsidStr)),
						)
						return
					}
				}
			}
		}
	}
}

// printPrettyRR prints a pretty RR
func (p Printer) printPrettyRR(a dns.RR, doWhois bool) {
	// Initialize existingRRs map if it doesn't exist
	if p.existingRRs == nil {
		p.existingRRs = make(map[string]bool)
	}

	val := strings.TrimSpace(strings.Join(strings.Split(a.String(), dns.TypeToString[a.Header().Rrtype])[1:], ""))
	rrSignature := fmt.Sprintf("%s %d %s %s", a.Header().Name, a.Header().Ttl, dns.TypeToString[a.Header().Rrtype], val)
	if ok := p.existingRRs[rrSignature]; ok {
		return
	} else {
		p.existingRRs[rrSignature] = true
	}

	ttl := fmt.Sprintf("%d", a.Header().Ttl)
	if p.Opts.PrettyTTLs {
		ttl = (time.Duration(a.Header().Ttl) * time.Second).String()
	}

	if doWhois && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		resp, err := whois.Query(val)
		if err != nil {
			log.Warnf("bgp.tools query: %s", err)
		} else {
			val += util.Color("teal", fmt.Sprintf(" (AS%d %s)", resp.AS, resp.ASName))
		}
	}

	if p.Opts.ValueOnly {
		util.MustWriteln(p.Out, val)
	} else {
		util.MustWritef(p.Out, "%s %s %s %s\n",
			util.Color("purple", a.Header().Name),
			util.Color("green", ttl),
			util.Color("magenta", dns.TypeToString[a.Header().Rrtype]),
			val,
		)
	}
}

func (p Printer) PrintPretty(i int, reply *dns.Msg) {
	if p.Opts.ShowQuestion {
		util.MustWriteln(p.Out, util.Color("white", "Question:"))
		for _, a := range reply.Question {
			util.MustWritef(p.Out, "%s %s\n",
				util.Color("purple", a.Name),
				util.Color("magenta", dns.TypeToString[a.Qtype]),
			)
		}
	}
	if p.Opts.ShowAnswer && len(reply.Answer) > 0 {
		if p.Opts.ShowQuestion || p.Opts.ShowAuthority || p.Opts.ShowAdditional {
			util.MustWriteln(p.Out, util.Color("white", "Answer:"))
		}
		for _, a := range reply.Answer {
			p.printPrettyRR(a, p.Opts.Whois)
		}
	}
	if p.Opts.ShowAuthority && len(reply.Ns) > 0 {
		util.MustWriteln(p.Out, util.Color("white", "Authority:"))
		for _, a := range reply.Ns {
			p.printPrettyRR(a, p.Opts.Whois)
		}
	}
	if p.Opts.ShowAdditional && len(reply.Extra) > 0 {
		util.MustWriteln(p.Out, util.Color("white", "Additional:"))
		for _, a := range reply.Extra {
			p.printPrettyRR(a, p.Opts.Whois)
		}
	}

	// Print separator if there is more than one query
	if (p.Opts.ShowQuestion || p.Opts.ShowAuthority || p.Opts.ShowAdditional) &&
		(p.NumReplies > 0 && i != p.NumReplies-1) {
		util.MustWritef(p.Out, "\n──\n\n")
	}

	if p.Opts.ShowStats {
		util.MustWriteln(p.Out, util.Color("white", "Stats:"))
		util.MustWritef(p.Out, "Received %s from %s in %s (%s)\n",
			util.Color("purple", fmt.Sprintf("%d B", reply.Len())),
			util.Color("green", p.Server),
			util.Color("teal", p.QueryTime.Round(100*time.Microsecond)),
			util.Color("magenta", time.Now().Format("15:04:05 01-02-2006 MST")),
		)

		flags := ""
		if reply.MsgHdr.Response {
			flags = "qr"
		}
		if reply.MsgHdr.Authoritative {
			flags = "aa"
		}
		if reply.MsgHdr.Truncated {
			flags = "tc"
		}
		if reply.MsgHdr.RecursionDesired {
			flags = "rd"
		}
		if reply.MsgHdr.RecursionAvailable {
			flags = "ra"
		}
		if reply.MsgHdr.Zero {
			flags = "z"
		}
		if reply.MsgHdr.AuthenticatedData {
			flags = "ad"
		}
		if reply.MsgHdr.CheckingDisabled {
			flags = "cd"
		}

		util.MustWritef(p.Out, "Opcode: %s Status: %s ID %s: Flags: %s (%s Q %s A %s N %s E)\n",
			util.Color("magenta", dns.OpcodeToString[reply.MsgHdr.Opcode]),
			util.Color("teal", dns.RcodeToString[reply.MsgHdr.Rcode]),
			util.Color("green", fmt.Sprintf("%d", reply.MsgHdr.Id)),
			util.Color("purple", flags),
			util.Color("purple", fmt.Sprintf("%d", len(reply.Question))),
			util.Color("green", fmt.Sprintf("%d", len(reply.Answer))),
			util.Color("teal", fmt.Sprintf("%d", len(reply.Ns))),
			util.Color("magenta", fmt.Sprintf("%d", len(reply.Extra))),
		)
	}
}
