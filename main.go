package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// CLI flags
type optsTemplate struct {
	Name                string   `short:"q" long:"qname" description:"Query name"`
	Server              string   `short:"s" long:"server" description:"DNS server"`
	Types               []string `short:"t" long:"type" description:"RR type"`
	Reverse             bool     `short:"x" long:"reverse" description:"Reverse lookup"`
	DNSSEC              bool     `short:"d" long:"dnssec" description:"Set the DO (DNSSEC OK) bit in the OPT record"`
	NSID                bool     `short:"n" long:"nsid" description:"Set EDNS0 NSID opt"`
	ClientSubnet        string   `long:"subnet" description:"Set EDNS0 client subnet"`
	Format              string   `short:"f" long:"format" description:"Output format (pretty, json, raw)" default:"pretty"`
	Chaos               bool     `short:"c" long:"chaos" description:"Use CHAOS query class"`
	ODoHProxy           string   `short:"p" long:"odoh-proxy" description:"ODoH proxy"`
	TLSVerify           bool     `short:"i" long:"tls-verify" description:"Enable TLS certificate verification"`
	Timeout             uint     `long:"timeout" description:"Upstream timeout in seconds" default:"10"`
	AuthoritativeAnswer bool     `long:"aa" description:"Set AA (Authoritative Answer) flag in query"`
	AuthenticData       bool     `long:"ad" description:"Set AD (Authentic Data) flag in query"`
	CheckingDisabled    bool     `long:"cd" description:"Set CD (Checking Disabled) flag in query"`
	RecursionDesired    bool     `long:"rd" description:"Set RD (Recursion Desired) flag in query"`
	RecursionAvailable  bool     `long:"ra" description:"Set RA (Recursion Available) flag in query"`
	Zero                bool     `long:"z" description:"Set Z (Zero) flag in query"`
	UDPBuffer           uint16   `long:"udp-buffer" description:"Set EDNS0 UDP size in query" default:"4096"`
	Verbose             bool     `short:"v" long:"verbose" description:"Show verbose log messages"`
	ShowVersion         bool     `short:"V" long:"version" description:"Show version and exit"`
}

var opts = optsTemplate{}

// Build process flags
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

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

// clearOpts sets the default values for the CLI options
func clearOpts() {
	opts = optsTemplate{}
	opts.RecursionDesired = true
	opts.TLSVerify = true
}

// parsePlusFlags parses a list of flags notated by +[no]flag and sets the corresponding opts fields
func parsePlusFlags(args []string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "+") && len(arg) > 3 {
			state := arg[1:3] != "no"
			flag := strings.ToLower(arg[3:])
			if state {
				flag = strings.ToLower(arg[1:])
			}

			v := reflect.ValueOf(opts)
			vT := v.Type()
			for i := 0; i < v.NumField(); i++ {
				fieldTag := vT.Field(i).Tag.Get("long")
				if vT.Field(i).Type == reflect.TypeOf(true) && fieldTag == flag {
					reflect.ValueOf(&opts).Elem().Field(i).SetBool(state)
					break
				}
			}
		}
	}
}

func queryFlags() string {
	flags := " "
	if opts.AuthoritativeAnswer {
		flags += "aa "
	}
	if opts.AuthenticData {
		flags += "ad "
	}
	if opts.CheckingDisabled {
		flags += "cd "
	}
	if opts.RecursionDesired {
		flags += "rd "
	}
	if opts.RecursionAvailable {
		flags += "ra "
	}
	if opts.Zero {
		flags += "Z "
	}

	// Remove trailing space
	return strings.TrimSpace(flags)
}

// driver is the "main" function for this program that accepts a flag slice for testing
func driver(args []string) error {
	_, err := flags.ParseArgs(&opts, args)
	if err != nil {
		if !strings.Contains(err.Error(), "Usage") {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	parsePlusFlags(args)

	// Enable debug logging in development releases
	if //noinspection GoBoolExpressions
	version == "dev" || opts.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	if opts.ShowVersion {
		fmt.Printf("https://github.com/natesales/q version %s (%s %s)\n", version, commit, date)
		return nil
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

	// Add non-flag RR types
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
		if opts.Name == "" && (strings.Contains(arg, ".") || strings.Contains(arg, ":")) && !strings.Contains(arg, "@") && !strings.Contains(arg, "/") && !strings.HasPrefix(arg, "-") {
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
			return fmt.Errorf("dns reverse: %s", err)
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
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			opts.Server = "https://cloudflare-dns.com/dns-query"
			log.Debugf("no server set, using %s", opts.Server)
		} else {
			opts.Server = conf.Servers[0]
			log.Debugf("found server %s from /etc/resolv.conf", opts.Server)
		}
	}

	//log.Debugf("using server %s", u.Address())

	var rrTypesSlice []uint16
	for rrType := range rrTypes {
		rrTypesSlice = append(rrTypesSlice, rrType)
	}
	answers, queryTime, err := resolve(
		opts.Name,
		opts.Chaos, opts.DNSSEC, opts.NSID,
		opts.ODoHProxy,
		rrTypesSlice,
		opts.AuthoritativeAnswer,
		opts.AuthenticData,
		opts.CheckingDisabled,
		opts.RecursionDesired,
		opts.RecursionAvailable,
		opts.Zero,
		opts.UDPBuffer,
		opts.ClientSubnet,
	)
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
	clearOpts()
	if err := driver(os.Args); err != nil {
		log.Fatal(err)
	}
}
