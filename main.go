package main

import (
	"encoding/json"
	"errors"
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
	Timeout   uint     `long:"timeout" description:"Upstream timeout in seconds" default:"10"`
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

// driver is the "main" function for this program that accepts a flag slice for testing
func driver(args []string) error {
	// Parse cli flags
	_, err := flags.ParseArgs(&opts, args)
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

	// Parse requested RR types
	var rrTypes = make(map[uint16]bool)
	for _, rrType := range opts.Types {
		typeCode, ok := dns.StringToType[strings.ToUpper(rrType)]
		if ok {
			rrTypes[typeCode] = true
		} else {
			return fmt.Errorf("%s is not a valid RR type", rrType)
		}
	}

	for _, arg := range args {
		// Find a server by @ symbol if it isn't set by flag
		if opts.Server == "" && strings.HasPrefix(arg, "@") {
			opts.Server = strings.TrimPrefix(arg, "@")
		}

		// Parse boolean options
		if strings.HasPrefix(arg, "+") {
			switch arg {
			case "+dnssec":
				opts.DNSSEC = true
			}
		}

		// Parse chaos class
		if strings.ToLower(arg) == "ch" {
			opts.Chaos = true
		}

		// Add non-flag RR types
		rrType, ok := dns.StringToType[strings.ToUpper(arg)]
		if ok {
			rrTypes[rrType] = true
		}

		// Set qname if not set by flag
		if opts.Name == "" && strings.Contains(arg, ".") && !strings.Contains(arg, "@") && !strings.Contains(arg, "/") && !strings.HasPrefix(arg, "-") {
			opts.Name = arg
		}
	}

	// If no RR types are defined, set a list of default ones
	if len(rrTypes) < 1 {
		for _, defaultRRType := range []string{"A", "AAAA", "NS", "MX", "TXT", "CNAME"} {
			rrType, _ := dns.StringToType[defaultRRType]
			rrTypes[rrType] = true
		}
	}

	// Reverse address if required
	if opts.Reverse {
		opts.Name, err = dns.ReverseAddr(opts.Name)
		if err != nil {
			return err
		}
		rrTypes[dns.StringToType["PTR"]] = true
	}

	// Log RR types
	if opts.Verbose {
		var rrTypeStrings []string
		for rrType := range rrTypes {
			rrTypeStrings = append(rrTypeStrings, dns.TypeToString[rrType])
		}
		log.Debugf("RR types: %+v", rrTypeStrings)
	}

	log.Debugf("qname %s", opts.Name)

	// Set default DNS server
	if opts.Server == "" {
		opts.Server = "https://cloudflare-dns.com/dns-query"
	}

	// Create the upstream server
	u, err := upstream.AddressToUpstream(opts.Server, &upstream.Options{
		Timeout:            time.Duration(opts.Timeout) * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		return fmt.Errorf("cannot create upstream %v", err)
	}

	if opts.OdohProxy != "" {
		log.Debugf("using ODoH proxy %s", opts.OdohProxy)
		if !strings.HasPrefix(u.Address(), "https") {
			return fmt.Errorf("upstream %s doesn't have an explicit HTTPS protocol", u.Address())
		}
		if !strings.HasPrefix(opts.OdohProxy, "https") {
			return fmt.Errorf("proxy %s doesn't have an explicit HTTPS protocol", opts.OdohProxy)
		}
	}

	log.Debugf("using server %s", u.Address())

	var rrTypesSlice []uint16
	for rrType := range rrTypes {
		rrTypesSlice = append(rrTypesSlice, rrType)
	}
	answers, queryTime, err := resolve(opts.Name, opts.Chaos, opts.DNSSEC, opts.OdohProxy, u, rrTypesSlice)
	if err != nil {
		return err
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
			return err
		}
		fmt.Println(string(marshalled))
	default:
		return errors.New("invalid output format")
	}

	return nil // nil error
}

func main() {
	if err := driver(os.Args); err != nil {
		log.Fatal(err)
	}
}
