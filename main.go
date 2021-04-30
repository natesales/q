package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// CLI flags
var opts struct {
	Name      string   `short:"q" long:"qname" description:"Query name"`
	Server    string   `short:"s" long:"server" description:"DNS server"`
	Types     []string `short:"t" long:"type" description:"RR type"`
	Reverse   bool     `short:"x" long:"reverse" description:"Reverse lookup"`
	DNSSEC    bool     `short:"d" long:"dnssec" description:"Request DNSSEC"`
	Format    string   `short:"f" long:"format" description:"Output format (pretty, json, raw)" default:"pretty"`
	Chaos     bool     `short:"c" long:"chaos" description:"Use CHAOS query class"`
	OdohProxy string   `short:"p" long:"odoh-proxy" description:"ODoH proxy"`
	Insecure  bool     `short:"i" long:"insecure" description:"Disable TLS certificate verification"`
	Timeout   uint     `short:"t" long:"timeout" description:"Upstream timeout in seconds" default:"10"`
	Verbose   bool     `short:"v" long:"verbose" description:"Show verbose log messages"`
}

var version = "dev" // Set by build process

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
	return fmt.Sprintf(colors[color], fmt.Sprint(args...))
}

func main() {
	// Parse cli flags
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		if !strings.Contains(err.Error(), "Usage") {
			log.Fatal(err)
		}
		os.Exit(1)
	}

	// Enable debug logging in development releases
	if //noinspection GoBoolExpressions
	version == "devel" || opts.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Find a server by @ symbol if it isn't set by flag
	if opts.Server == "" {
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "@") {
				opts.Server = strings.TrimPrefix(arg, "@")
			}
		}
	}

	// Parse requested RR types
	var rrTypes []uint16
	for _, rrType := range opts.Types {
		typeCode, ok := dns.StringToType[strings.ToUpper(rrType)]
		if ok {
			rrTypes = append(rrTypes, typeCode)
		} else {
			fmt.Printf("%s is not a valid RR type\n", rrType)
			os.Exit(1)
		}
	}

	// Add non-flag RR types
	for _, arg := range os.Args {
		rrType, ok := dns.StringToType[strings.ToUpper(arg)]
		if ok {
			rrTypes = append(rrTypes, rrType)
		}
	}

	// If no RR types are defined, set a list of default ones
	if len(rrTypes) < 1 {
		for _, defaultRRType := range []string{"A", "AAAA", "NS", "MX", "TXT", "CNAME"} {
			rrType, _ := dns.StringToType[defaultRRType]
			rrTypes = append(rrTypes, rrType)
		}
	}

	// Log RR types
	if opts.Verbose {
		var rrTypeStrings []string
		for _, rrType := range rrTypes {
			rrTypeStrings = append(rrTypeStrings, dns.TypeToString[rrType])
		}
		log.Debugf("RR types: %+v", rrTypeStrings)
	}

	// Set qname if not set by flag
	for _, arg := range os.Args {
		if strings.Contains(arg, ".") && !strings.Contains(arg, "@") {
			opts.Name = arg
		}
	}

	// Reverse address if required
	if opts.Reverse {
		opts.Name, err = dns.ReverseAddr(opts.Name)
		if err != nil {
			log.Fatal(err)
		}
		rrTypes = append(rrTypes, dns.StringToType["PTR"])
	}

	log.Debugf("qname %s", opts.Name)

	// Set default DNS server
	if opts.Server == "" {
		opts.Server = "https://cloudflare-dns.com/dns-query"
	}

	// Create the upstream server
	u, err := upstream.AddressToUpstream(opts.Server, upstream.Options{
		Timeout:            time.Duration(opts.Timeout) * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		log.Fatalf("cannot create upstream %v", err)
	}

	if opts.OdohProxy != "" {
		log.Debugf("using ODoH proxy %s", opts.OdohProxy)
		if !strings.HasPrefix(u.Address(), "https") {
			log.Warnf("upstream %s doesn't have an explicit HTTPS protocol", u.Address())
		}
	}

	log.Debugf("using server %s\n", u.Address())

	answers, queryTime, err := Resolve(opts.Name, opts.Chaos, opts.OdohProxy, u, rrTypes)
	if err != nil {
		log.Fatal(err)
	}

	// Print answers
	switch opts.Format {
	case "pretty":
		for _, a := range answers {
			fmt.Printf("%s %s %s %s\n",
				color("purple", a.Header().Name),
				color("green", time.Duration(a.Header().Ttl)*time.Second),
				color("magenta", dns.TypeToString[a.Header().Rrtype]),
				strings.TrimSpace(strings.Join(strings.Split(a.String(), dns.TypeToString[a.Header().Rrtype])[1:], "")),
			)
		}
	case "raw":
		for _, a := range answers {
			fmt.Println(a.String())
		}
		fmt.Printf(";; Received %d answers from %s in %s\n", len(answers), opts.Server, queryTime.Round(time.Millisecond))
	case "json":
		// Marshal answers to JSON
		marshalled, err := json.Marshal(struct {
			Server    string
			QueryTime int64
			Answers   []dns.RR
		}{
			Server:    opts.Server,
			QueryTime: int64(queryTime / time.Millisecond),
			Answers:   answers,
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(marshalled))
	default:
		log.Fatal("Invalid output format")
	}
}
