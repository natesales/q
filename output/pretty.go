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
							util.Color(util.ColorWhite, "NSID:"),
							util.Color(util.ColorPurple, string(nsidStr)),
						)
						return
					}
				}
			}
		}
	}
}

// ptr resolves an IP address (not an arpa FQDN) to its PTR record
func (p Printer) ptr(ip string) (string, error) {
	// Initialize ptrCache if it doesn't exist
	if p.ptrCache == nil {
		p.ptrCache = make(map[string]string)
	}

	// Return the result from cache if we already have it
	if ptr, ok := p.ptrCache[ip]; ok {
		return ptr, nil
	}

	// Create PTR query
	qname, err := dns.ReverseAddr(ip)
	if err != nil {
		log.Fatalf("error reversing PTR record: %s", err)
	}
	msg := dns.Msg{}
	msg.SetQuestion(qname, dns.TypePTR)

	// Resolve qname and cache result
	resp, err := (*p.Transport).Exchange(&msg)
	if err != nil {
		return "", err
	}

	// Cache and return
	if len(resp.Answer) > 0 {
		p.ptrCache[ip] = resp.Answer[0].(*dns.PTR).Ptr
		return p.ptrCache[ip], nil
	}

	// No value
	return "", fmt.Errorf("no PTR record found for %s", ip)
}

// printPrettyRR prints a pretty RR
func (p Printer) printPrettyRR(a dns.RR, doWhois, doResolveIPs bool) {
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
		if p.Opts.ShortTTLs {
			ttl = strings.ReplaceAll(ttl, "0s", "")
			ttl = strings.ReplaceAll(ttl, "0m", "")
		}
	}

	// Copy val now before modifying it with a suffix
	valCopy := val

	// Handle whois
	if doWhois && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		resp, err := whois.Query(valCopy)
		if err != nil {
			log.Warnf("bgp.tools query: %s", err)
		} else {
			val += util.Color(util.ColorTeal, fmt.Sprintf(" (AS%d %s)", resp.AS, resp.ASName))
		}
	}

	// Handle PTR resolution
	if doResolveIPs && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		if ptr, err := p.ptr(valCopy); err == nil {
			val += util.Color(util.ColorMagenta, fmt.Sprintf(" (%s)", ptr))
		} else {
			log.Warnf("PTR resolution: %s", err)
		}
	}

	if p.Opts.ValueOnly {
		util.MustWriteln(p.Out, val)
	} else {
		util.MustWritef(p.Out, "%s %s %s %s\n",
			util.Color(util.ColorPurple, a.Header().Name),
			util.Color(util.ColorGreen, ttl),
			util.Color(util.ColorMagenta, dns.TypeToString[a.Header().Rrtype]),
			val,
		)
	}
}

func (p Printer) printSection(rrs []dns.RR) {
	for _, a := range rrs {
		p.printPrettyRR(a, p.Opts.Whois, p.Opts.ResolveIPs)
	}
}

// flags returns a string of flags from a dns.Msg
func flags(m *dns.Msg) string {
	out := ""
	if m.MsgHdr.Response {
		out += "qr "
	}
	if m.MsgHdr.Authoritative {
		out += "aa "
	}
	if m.MsgHdr.Truncated {
		out += "tc "
	}
	if m.MsgHdr.RecursionDesired {
		out += "rd "
	}
	if m.MsgHdr.RecursionAvailable {
		out += "ra "
	}
	if m.MsgHdr.Zero {
		out += "z "
	}
	if m.MsgHdr.AuthenticatedData {
		out += "ad "
	}
	if m.MsgHdr.CheckingDisabled {
		out += "cd "
	}
	return strings.TrimSuffix(out, " ")
}

func (p Printer) PrintPretty(i int, reply *dns.Msg) {
	if p.Opts.ShowQuestion {
		util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Question:"))
		for _, a := range reply.Question {
			util.MustWritef(p.Out, "%s %s\n",
				util.Color(util.ColorPurple, a.Name),
				util.Color(util.ColorMagenta, dns.TypeToString[a.Qtype]),
			)
		}
	}
	if p.Opts.ShowAnswer && len(reply.Answer) > 0 {
		if p.Opts.ShowQuestion || p.Opts.ShowAuthority || p.Opts.ShowAdditional {
			util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Answer:"))
		}
		p.printSection(reply.Answer)
	}
	if p.Opts.ShowAuthority && len(reply.Ns) > 0 {
		util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Authority:"))
		p.printSection(reply.Ns)
	}
	if p.Opts.ShowAdditional && len(reply.Extra) > 0 {
		util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Additional:"))
		p.printSection(reply.Extra)
	}

	// Print separator if there is more than one query
	if (p.Opts.ShowQuestion || p.Opts.ShowAuthority || p.Opts.ShowAdditional) &&
		(p.NumReplies > 0 && i != p.NumReplies-1) {
		util.MustWritef(p.Out, "\n──\n\n")
	}

	if p.Opts.ShowStats {
		util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Stats:"))
		util.MustWritef(p.Out, "Received %s from %s in %s (%s)\n",
			util.Color(util.ColorPurple, fmt.Sprintf("%d B", reply.Len())),
			util.Color(util.ColorGreen, p.Server),
			util.Color(util.ColorTeal, p.QueryTime.Round(100*time.Microsecond)),
			util.Color(util.ColorMagenta, time.Now().Format("15:04:05 01-02-2006 MST")),
		)

		util.MustWritef(p.Out, "Opcode: %s Status: %s ID %s: Flags: %s (%s Q %s A %s N %s E)\n",
			util.Color(util.ColorMagenta, dns.OpcodeToString[reply.MsgHdr.Opcode]),
			util.Color(util.ColorTeal, dns.RcodeToString[reply.MsgHdr.Rcode]),
			util.Color(util.ColorGreen, fmt.Sprintf("%d", reply.MsgHdr.Id)),
			util.Color(util.ColorPurple, flags(reply)),
			util.Color(util.ColorPurple, fmt.Sprintf("%d", len(reply.Question))),
			util.Color(util.ColorGreen, fmt.Sprintf("%d", len(reply.Answer))),
			util.Color(util.ColorTeal, fmt.Sprintf("%d", len(reply.Ns))),
			util.Color(util.ColorMagenta, fmt.Sprintf("%d", len(reply.Extra))),
		)
	}
}
