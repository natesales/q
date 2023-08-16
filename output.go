package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	whois "github.com/natesales/bgptools-go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var existingRRs = map[string]bool{}

// ANSI colors
var colors = map[string]string{
	"black":   "\033[1;30m%s\033[0m",
	"red":     "\033[1;31m%s\033[0m",
	"green":   "\033[1;32m%s\033[0m",
	"yellow":  "\033[1;33m%s\033[0m",
	"purple":  "\033[1;34m%s\033[0m",
	"magenta": "\033[1;35m%s\033[0m",
	"teal":    "\033[1;36m%s\033[0m",
	"white":   "\033[1;37m%s\033[0m",
}

// color returns a color formatted string
func color(color string, args ...interface{}) string {
	if opts.Color {
		return fmt.Sprintf(colors[color], fmt.Sprint(args...))
	} else {
		return fmt.Sprint(args...)
	}
}

func mustWriteln(out io.Writer, s string) {
	if _, err := out.Write([]byte(s + "\n")); err != nil {
		log.Fatal(err)
	}
}

func mustWritef(out io.Writer, format string, a ...interface{}) {
	if _, err := out.Write([]byte(fmt.Sprintf(format, a...))); err != nil {
		log.Fatal(err)
	}
}

// printPrettyRR prints a pretty RR
func printPrettyRR(a dns.RR, doWhois bool, out io.Writer) {
	val := strings.TrimSpace(strings.Join(strings.Split(a.String(), dns.TypeToString[a.Header().Rrtype])[1:], ""))
	rrSignature := fmt.Sprintf("%s %d %s %s", a.Header().Name, a.Header().Ttl, dns.TypeToString[a.Header().Rrtype], val)
	if ok := existingRRs[rrSignature]; ok {
		return
	} else {
		existingRRs[rrSignature] = true
	}

	ttl := fmt.Sprintf("%d", a.Header().Ttl)
	if opts.PrettyTTLs {
		ttl = fmt.Sprintf("%s", time.Duration(a.Header().Ttl)*time.Second)
	}

	if doWhois && (a.Header().Rrtype == dns.TypeA || a.Header().Rrtype == dns.TypeAAAA) {
		resp, err := whois.Query(val)
		if err != nil {
			log.Warnf("bgp.tools query: %s", err)
		} else {
			val += color("teal", fmt.Sprintf(" (AS%d %s)", resp.AS, resp.ASName))
		}
	}

	if opts.ValueOnly {
		mustWriteln(out, val)
	} else {
		mustWritef(out, "%s %s %s %s\n",
			color("purple", a.Header().Name),
			color("green", ttl),
			color("magenta", dns.TypeToString[a.Header().Rrtype]),
			val,
		)
	}
}

func prettyPrintNSID(opt []*dns.Msg, out io.Writer) {
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
						mustWritef(out, "%s %s\n",
							color("white", "NSID:"),
							color("purple", string(nsidStr)),
						)
						return
					}
				}
			}
		}
	}
}

func display(replies []*dns.Msg, server string, queryTime time.Duration, out io.Writer) error {
	switch opts.Format {
	case "pretty":
		if opts.NSID {
			prettyPrintNSID(replies, out)
		}
	}

	for i, reply := range replies {
		// Print answers
		switch opts.Format {
		case "pretty":
			if opts.ShowQuestion {
				mustWriteln(out, color("white", "Question:"))
				for _, a := range reply.Question {
					mustWritef(out, "%s %s\n",
						color("purple", a.Name),
						color("magenta", dns.TypeToString[a.Qtype]),
					)
				}
			}
			if opts.ShowAnswer && len(reply.Answer) > 0 {
				if opts.ShowQuestion || opts.ShowAuthority || opts.ShowAdditional {
					mustWriteln(out, color("white", "Answer:"))
				}
				for _, a := range reply.Answer {
					printPrettyRR(a, opts.Whois, out)
				}
			}
			if opts.ShowAuthority && len(reply.Ns) > 0 {
				mustWriteln(out, color("white", "Authority:"))
				for _, a := range reply.Ns {
					printPrettyRR(a, opts.Whois, out)
				}
			}
			if opts.ShowAdditional && len(reply.Extra) > 0 {
				mustWriteln(out, color("white", "Additional:"))
				for _, a := range reply.Extra {
					printPrettyRR(a, opts.Whois, out)
				}
			}

			// Print separator if there is more than one query
			if (opts.ShowQuestion || opts.ShowAuthority || opts.ShowAdditional) && (len(replies) > 0 && i != len(replies)-1) {
				mustWritef(out, "\n──\n\n")
			}

			if opts.ShowStats {
				mustWriteln(out, color("white", "Stats:"))
				mustWritef(out, "Received %s from %s in %s (%s)\n",
					color("purple", fmt.Sprintf("%d B", reply.Len())),
					color("green", server),
					color("teal", queryTime.Round(100*time.Microsecond)),
					color("magenta", time.Now().Format("15:04:05 01-02-2006 MST")),
				)
			}
		case "raw":
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
			if opts.ShowQuestion && len(reply.Question) > 0 {
				s += "\n;; QUESTION SECTION:\n"
				for _, r := range reply.Question {
					s += r.String() + "\n"
				}
			}
			if opts.ShowAnswer && len(reply.Answer) > 0 {
				s += "\n;; ANSWER SECTION:\n"
				for _, r := range reply.Answer {
					if r != nil {
						s += r.String() + "\n"
					}
				}
			}
			if opts.ShowAuthority && len(reply.Ns) > 0 {
				s += "\n;; AUTHORITY SECTION:\n"
				for _, r := range reply.Ns {
					if r != nil {
						s += r.String() + "\n"
					}
				}
			}
			if opts.ShowAdditional && len(reply.Extra) > 0 && (opt == nil || len(reply.Extra) > 1) {
				s += "\n;; ADDITIONAL SECTION:\n"
				for _, r := range reply.Extra {
					if r != nil && r.Header().Rrtype != dns.TypeOPT {
						s += r.String() + "\n"
					}
				}
			}
			mustWriteln(out, s)

			if opts.ShowStats {
				mustWritef(out, ";; Received %d B\n", reply.Len())
				mustWritef(out, ";; Time %s\n", time.Now().Format("15:04:05 01-02-2006 MST"))
				mustWritef(out, ";; From %s in %s\n", server, queryTime.Round(100*time.Microsecond))
			}

			// Print separator if there is more than one query
			if len(replies) > 0 && i != len(replies)-1 {
				mustWritef(out, "\n--\n\n")
			}
		case "json", "yml", "yaml":
			body := struct {
				Server    string
				QueryTime int64
				Answers   []dns.RR
				ID        uint16
				Truncated bool
			}{
				Server:    opts.Server,
				QueryTime: int64(queryTime / time.Millisecond),
				Answers:   reply.Answer,
				ID:        reply.Id,
				Truncated: reply.Truncated,
			}
			var b []byte
			var err error
			if opts.Format == "json" {
				b, err = json.Marshal(body)
			} else { // yaml
				b, err = yaml.Marshal(body)
			}
			if err != nil {
				return err
			}

			mustWriteln(out, string(b))
		default:
			return fmt.Errorf("invalid output format")
		}
	}

	return nil
}
