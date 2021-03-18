package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

const defaultDnsServer = "https://dns.cloudflare.com/dns-query"

var version = "dev" // Set by build process
var versionBanner = "q command line DNS client (https://github.com/natesales/q) version " + version + "\n"
var usage = versionBanner + `
Usage:
  q [OPTIONS] @<protocol>://<server>:[port] <rr types> <qname>

Options:
  -d, --dnssec  Request DNSSEC
  -r, --raw     Output raw DNS string format
  -h, --help    Display help menu
  -v, --verbose Enable verbose logging
  -q, --quiet   Don't display DNS response

Protocols:
  dns    RFC 1034 UDP/TCP DNS
  tls    RFC 7858 DNS over TLS
  https  RFC 8484 DNS over HTTPS
  quic   draft-ietf-dprive-dnsoquic-02 DNS over QUIC`

// ANSI colors
var (
	Black   = color("\033[1;30m%s\033[0m")
	Red     = color("\033[1;31m%s\033[0m")
	Green   = color("\033[1;32m%s\033[0m")
	Yellow  = color("\033[1;33m%s\033[0m")
	Purple  = color("\033[1;34m%s\033[0m")
	Magenta = color("\033[1;35m%s\033[0m")
	Teal    = color("\033[1;36m%s\033[0m")
	White   = color("\033[1;37m%s\033[0m")
)

func color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

// cliArgs stores parsed query information
type cliArgs struct {
	RRTypes []uint16
	Qname   string
	Server  string
	DNSSEC  bool
	Raw     bool
	Verbose bool
	Quiet   bool
}

func main() {
	args := cliArgs{}

	// Parse CLI arguments
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "@") { // DNS server
			args.Server = strings.TrimPrefix(arg, "@")
		} else if strings.HasPrefix(arg, "-") { // Flags
			switch arg {
			case "-d", "--dnssec":
				args.DNSSEC = true
			case "-r", "--raw":
				args.Raw = true
			case "-h", "--help":
				fmt.Println(usage)
				os.Exit(0)
			case "-v", "--verbose":
				args.Verbose = true
			case "-q", "--quiet":
				args.Quiet = true
			default:
				fmt.Printf("unknown flag %s\n", arg)
				fmt.Println(usage)
				os.Exit(1)
			}
		} else if strings.Contains(arg, ".") { // QNAME
			args.Qname = arg
		} else { // RR types
			rrType, ok := dns.StringToType[strings.ToUpper(arg)]
			if ok {
				args.RRTypes = append(args.RRTypes, rrType)
			} else {
				fmt.Printf("%s is not a valid RR type\n", arg)
				os.Exit(1)
			}
		}
	}

	// Validate query info
	if args.Server == "" {
		args.Server = defaultDnsServer
	}

	// If no RR types are defined, set a list of default ones
	if len(args.RRTypes) < 1 {
		for _, defaultRRType := range []string{"A", "AAAA", "NS", "TXT", "CNAME"} {
			rrType, _ := dns.StringToType[defaultRRType]
			args.RRTypes = append(args.RRTypes, rrType)
		}
	}

	if args.Verbose {
		fmt.Printf(Teal("INFO: ")+"%+v\n", args)
	}

	// Create the upstream server
	u, err := upstream.AddressToUpstream(args.Server, upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Fatalf(Teal("INFO: ")+"Cannot create an upstream: %s", err)
	}

	if args.Verbose {
		fmt.Printf(Teal("INFO: ")+"using server %s\n", u.Address())
	}

	// Iterate over requested RR types
	for _, qType := range args.RRTypes {
		req := dns.Msg{}

		// Create the DNS question
		if args.DNSSEC {
			req.SetEdns0(4096, true)
		}
		req.RecursionDesired = true
		req.Question = []dns.Question{
			{
				Name:   dns.Fqdn(args.Qname),
				Qtype:  qType,
				Qclass: dns.ClassINET,
			},
		}

		// Send question to server
		reply, err := u.Exchange(&req)
		if err != nil {
			log.Fatalf(Red("ERR: ")+"DNS request: %s", err)
		}

		// Print answers
		for _, answer := range reply.Answer {
			if !args.Quiet {
				if args.Raw {
					fmt.Println(answer.String())
				} else {
					hdr := answer.Header()
					fmt.Printf("%s %s %s %s\n",
						Purple(hdr.Name),
						Green(time.Duration(hdr.Ttl)*time.Second),
						Magenta(dns.TypeToString[hdr.Rrtype]),
						strings.TrimSpace(strings.Join(strings.Split(answer.String(), dns.TypeToString[hdr.Rrtype])[1:], "")),
					)
				}
			}
		}
	}
}
