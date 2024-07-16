package output

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	whois "github.com/natesales/bgptools-go"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/util"
)

// PrettyPrintNSID prints the NSID from a slice of entries
func (p Printer) PrettyPrintNSID(entries []*Entry, printPrefix bool) {
	for _, entry := range entries {
		for _, r := range entry.Replies {
			for _, o := range r.Extra {
				if o.Header().Rrtype == dns.TypeOPT {
					for _, e := range o.(*dns.OPT).Option {
						if e.Option() == dns.EDNS0NSID {
							nsidStr, err := hex.DecodeString(e.String())
							if err != nil {
								log.Warnf("error decoding NSID: %s", err)
								return
							}
							var suffix string
							if len(entries) > 1 {
								suffix = fmt.Sprintf(" (%s)", entry.Server)
							}

							var prefix string
							if printPrefix {
								prefix = util.Color(util.ColorWhite, "NSID:") + " "
							}

							util.MustWritef(p.Out, "%s%s%s\n",
								prefix,
								util.Color(util.ColorPurple, string(nsidStr)),
								suffix,
							)
							return
						}
					}
				}
			}
		}
	}
}

// parseRR converts an RR into a pretty string and returns the qname, ttl, type, value, and whether to skip printing it because it's a duplicate
func (e *Entry) parseRR(a dns.RR, opts *cli.Flags) *RR {
	// Initialize existingRRs map if it doesn't exist
	if e.existingRRs == nil {
		e.existingRRs = make(map[string]bool)
	}

	val := a.String()
	for _, cut := range []string{a.Header().Name, strconv.Itoa(int(a.Header().Ttl)), dns.ClassToString[a.Header().Class], dns.TypeToString[a.Header().Rrtype]} {
		val = strings.TrimSpace(
			strings.TrimPrefix(val, cut),
		)
	}

	rrSignature := fmt.Sprintf("%s %d %s %s %s", a.Header().Name, a.Header().Ttl, dns.TypeToString[a.Header().Rrtype], val, e.Server)
	// Skip if we've already printed this RR
	if ok := e.existingRRs[rrSignature]; ok {
		return nil
	}
	e.existingRRs[rrSignature] = true

	ttl := fmt.Sprintf("%d", a.Header().Ttl)
	if opts.PrettyTTLs {
		ttl = (time.Duration(a.Header().Ttl) * time.Second).String()
		if opts.ShortTTLs {
			ttl = strings.ReplaceAll(ttl, "m0s", "m")
			ttl = strings.ReplaceAll(ttl, "h0m", "h")
		}
	}

	// Copy val now before modifying it with a suffix
	valCopy := val

	// Handle whois
	if opts.Whois && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		resp, err := whois.Query(valCopy)
		if err != nil {
			log.Warnf("bgp.tools query: %s", err)
		} else {
			val += util.Color(util.ColorTeal, fmt.Sprintf(" (AS%d %s)", resp.AS, resp.ASName))
		}
	}

	// Handle PTR resolution
	if opts.ResolveIPs && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		val += util.Color(util.ColorMagenta, fmt.Sprintf(" (%s)", e.PTRs[valCopy]))
	}

	// Server suffix
	if len(opts.Server) > 1 {
		val += util.Color(util.ColorTeal, fmt.Sprintf(" (%s)", e.Server))
	}

	return &RR{
		util.Color(util.ColorPurple, a.Header().Name),
		util.Color(util.ColorGreen, ttl),
		util.Color(util.ColorMagenta, dns.TypeToString[a.Header().Rrtype]),
		val,
	}
}

// sortSlices sorts a slice of slices of strings by the nth element of each slice
func sortSlices(s [][]string, n int) [][]string {
	sort.Slice(s, func(i, j int) bool {
		return s[i][n] < s[j][n]
	})
	return s
}

// sortToPrint sorts a slice of records first by record type, then by value
func sortToPrint(s [][]string) [][]string {
	// Organize by record type
	records := make(map[string][][]string)
	for _, record := range s {
		rrType := record[2]
		records[rrType] = append(records[rrType], record)
	}

	// Sort each record type
	for rrType, recs := range records {
		records[rrType] = sortSlices(recs, 3)
	}

	// Sort record types
	var sortedTypes []string
	for rrType := range records {
		sortedTypes = append(sortedTypes, rrType)
	}
	sort.Strings(sortedTypes)

	// Build final result
	var result [][]string
	for _, rrType := range sortedTypes {
		result = append(result, records[rrType]...)
	}
	return result
}

type RR struct {
	Name, TTL, Type, Value string
}

func toRRs(rrs []dns.RR, e *Entry, p *Printer) []RR {
	var out []RR
	for _, rr := range rrs {
		if rr := e.parseRR(rr, p.Opts); rr != nil {
			out = append(out, *rr)
		}
	}

	return out
}

// printSection prints a slice of RRs
func (p Printer) printSection(rrs []RR) {
	var toPrint [][]string

	for _, a := range rrs {
		if p.Opts.ValueOnly {
			util.MustWriteln(p.Out, a.Value)
			continue
		}

		if len(a.TTL) > p.longestTTL {
			p.longestTTL = len(a.TTL)
		}
		if len(a.Type) > p.longestRRType {
			p.longestRRType = len(a.Type)
		}

		toPrint = append(toPrint, []string{a.Name, a.TTL, a.Type, a.Value})
	}

	// Sort by record type
	toPrint = sortToPrint(toPrint)

	for _, a := range toPrint {
		if p.Opts.Format == "column" {
			util.MustWritef(p.Out, "%"+strconv.Itoa(p.longestRRType)+"s %-"+strconv.Itoa(p.longestTTL)+"s %s\n", a[2], a[1], a[3])
		} else {
			util.MustWritef(p.Out, "%s %s %s %s\n", a[0], a[1], a[2], a[3])
		}
	}
}

// PrintColumn prints an entry slice in column format
func (p Printer) PrintColumn(entries []*Entry) {
	var answers []RR
	for _, e := range entries {
		for _, r := range e.Replies {
			rrs := toRRs(r.Answer, e, &p)
			answers = append(answers, rrs...)
		}
	}

	p.printSection(answers)
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

func (p Printer) PrintPretty(entries []*Entry) {
	for _, entry := range entries {
		for i, reply := range entry.Replies {
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
				p.printSection(toRRs(reply.Answer, entry, &p))
			}
			if p.Opts.ShowAuthority && len(reply.Ns) > 0 {
				util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Authority:"))
				p.printSection(toRRs(reply.Ns, entry, &p))
			}
			if p.Opts.ShowAdditional && len(reply.Extra) > 0 {
				util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Additional:"))
				p.printSection(toRRs(reply.Extra, entry, &p))
			}

			// Print separator if there is more than one query
			if (p.Opts.ShowQuestion || p.Opts.ShowAuthority || p.Opts.ShowAdditional) &&
				(len(entry.Replies) > 0 && i != len(entry.Replies)-1) {
				util.MustWritef(p.Out, "\n──\n\n")
			}

			if p.Opts.ShowStats {
				util.MustWriteln(p.Out, util.Color(util.ColorWhite, "Stats:"))
				util.MustWritef(p.Out, "Received %s from %s in %s (%s)\n",
					util.Color(util.ColorPurple, fmt.Sprintf("%d B", reply.Len())),
					util.Color(util.ColorGreen, entry.Server),
					util.Color(util.ColorTeal, entry.Time.Round(100*time.Microsecond)),
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
	}
}
