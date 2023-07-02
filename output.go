package main

import (
	"encoding/json"
	"fmt"
	whois "github.com/natesales/bgptools-go"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var existingRRs = map[string]bool{}

// printPrettyRR prints a pretty RR
func printPrettyRR(a dns.RR, doWhois bool) {
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
		fmt.Println(val)
	} else {
		fmt.Printf("%s %s %s %s\n",
			color("purple", a.Header().Name),
			color("green", ttl),
			color("magenta", dns.TypeToString[a.Header().Rrtype]),
			val,
		)
	}
}

func display(replies []*dns.Msg, server string, queryTime time.Duration) error {
	for i, reply := range replies {
		// Print answers
		switch opts.Format {
		case "pretty":
			if opts.ShowQuestion {
				fmt.Println(color("white", "Question:"))
				for _, a := range reply.Question {
					fmt.Printf("%s %s\n",
						color("purple", a.Name),
						color("magenta", dns.TypeToString[a.Qtype]),
					)
				}
			}
			if opts.ShowAnswer && len(reply.Answer) > 0 {
				if opts.ShowQuestion || opts.ShowAuthority || opts.ShowAdditional {
					fmt.Println(color("white", "Answer:"))
				}
				for _, a := range reply.Answer {
					printPrettyRR(a, opts.Whois)
				}
			}
			if opts.ShowAuthority && len(reply.Ns) > 0 {
				fmt.Println(color("white", "Authority:"))
				for _, a := range reply.Ns {
					printPrettyRR(a, opts.Whois)
				}
			}
			if opts.ShowAdditional && len(reply.Extra) > 0 {
				fmt.Println(color("white", "Additional:"))
				for _, a := range reply.Extra {
					printPrettyRR(a, opts.Whois)
				}
			}

			// Print separator if there is more than one query
			if (opts.ShowQuestion || opts.ShowAuthority || opts.ShowAdditional) && (len(replies) > 0 && i != len(replies)-1) {
				fmt.Printf("\n──\n\n")
			}

			if opts.ShowStats {
				fmt.Println(color("white", "Stats:"))
				fmt.Printf("Received %s from %s in %s (%s)\n",
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
			fmt.Println(s)

			if opts.ShowStats {
				fmt.Printf(";; Received %d B\n", reply.Len())
				fmt.Printf(";; Time %s\n", time.Now().Format("15:04:05 01-02-2006 MST"))
				fmt.Printf(";; From %s in %s\n", server, queryTime.Round(100*time.Microsecond))
			}

			// Print separator if there is more than one query
			if len(replies) > 0 && i != len(replies)-1 {
				fmt.Printf("\n--\n\n")
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
			fmt.Println(string(b))
		default:
			return fmt.Errorf("invalid output format")
		}
	}

	return nil
}
