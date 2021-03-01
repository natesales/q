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

var version = "dev" // Set by build process
var versionBanner = "q CLI DNS client (https://github.com/natesales/q) version " + version + "\n"
var usage = versionBanner + `
Usage:
  q @<protocol>://<server>:[port] <rr types> <qname> [OPTIONS]

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

// cliArgs stores parsed query information
type cliArgs struct {
	RRTypes []uint16
	Qname   string
	Server  string
	DNSSEC  bool
	Raw     bool
	Verbose bool
}

func main() {
	args := cliArgs{}

	// Parse CLI arguments
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "@") { // DNS server
			args.Server = strings.TrimPrefix(arg, "@")
		} else if strings.Contains(arg, "-") { // Flags
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
			default:
				fmt.Printf("unknown flag %s\n", arg)
				fmt.Println(usage)
				os.Exit(1)
			}
		} else if strings.Contains(arg, ".") { // QNAME
			args.Qname = arg
		} else { // RR types
			rrType, ok := dns.StringToType[arg]
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
		fmt.Println("server is not defined")
		fmt.Println(usage)
		os.Exit(1)
	}
	if len(args.RRTypes) < 1 {
		fmt.Println("no RR types are defined")
		fmt.Println(usage)
		os.Exit(1)
	}

	if args.Verbose {
		fmt.Printf("%+v\n", args)
	}

	// Create the upstream server
	u, err := upstream.AddressToUpstream(args.Server, upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	if args.Verbose {
		fmt.Printf("using server %s\n", u.Address())
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
			log.Fatalf("cannot make the DNS request: %s", err)
		}

		// Print answers
		for _, answer := range reply.Answer {
			if args.Raw {
				fmt.Println(answer.String())
			} else {
				hdr := answer.Header()
				fmt.Printf("%s %s %s %s\n",
					hdr.Name,
					time.Duration(hdr.Ttl)*time.Second,
					dns.TypeToString[hdr.Rrtype],
					strings.TrimSpace(strings.Join(strings.Split(answer.String(), dns.TypeToString[hdr.Rrtype])[1:], "")),
				)
			}
		}
	}
}
