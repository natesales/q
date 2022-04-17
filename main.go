package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/natesales/q/transport"
	log "github.com/sirupsen/logrus"
)

// CLI flags
type optsTemplate struct {
	Name         string   `short:"q" long:"qname" description:"Query name"`
	Server       string   `short:"s" long:"server" description:"DNS server"`
	Types        []string `short:"t" long:"type" description:"RR type"`
	Reverse      bool     `short:"x" long:"reverse" description:"Reverse lookup"`
	DNSSEC       bool     `short:"d" long:"dnssec" description:"Set the DO (DNSSEC OK) bit in the OPT record"`
	NSID         bool     `short:"n" long:"nsid" description:"Set EDNS0 NSID opt"`
	ClientSubnet string   `long:"subnet" description:"Set EDNS0 client subnet"`
	Format       string   `short:"f" long:"format" description:"Output format (pretty, json, raw)" default:"pretty"`
	Chaos        bool     `short:"c" long:"chaos" description:"Use CHAOS query class"`
	ODoHProxy    string   `short:"p" long:"odoh-proxy" description:"ODoH proxy"`
	Timeout      uint16   `long:"timeout" description:"Query timeout in seconds" default:"10"`
	Pad          bool     `long:"pad" description:"Set EDNS0 padding"`

	// Header flags
	AuthoritativeAnswer bool `long:"aa" description:"Set AA (Authoritative Answer) flag in query"`
	AuthenticData       bool `long:"ad" description:"Set AD (Authentic Data) flag in query"`
	CheckingDisabled    bool `long:"cd" description:"Set CD (Checking Disabled) flag in query"`
	RecursionDesired    bool `long:"rd" description:"Set RD (Recursion Desired) flag in query"`
	RecursionAvailable  bool `long:"ra" description:"Set RA (Recursion Available) flag in query"`
	Zero                bool `long:"z" description:"Set Z (Zero) flag in query"`

	// TCP parameters
	TLSNoVerify   bool   `short:"i" long:"tls-no-verify" description:"Disable TLS certificate verification"`
	TLSMinVersion string `long:"tls-min-version" description:"Minimum TLS version to use" default:"1.0"`
	TLSMaxVersion string `long:"tls-max-version" description:"Maximum TLS version to use" default:"1.3"`

	// HTTP
	HTTPUserAgent string `long:"http-user-agent" description:"HTTP user agent" default:""`
	HTTPMethod    string `long:"http-method" description:"HTTP method" default:"GET"`

	// QUIC
	QUICALPNTokens        []string `long:"quic-alpn-tokens" description:"QUIC ALPN tokens" default:"doq" default:"doq-i11"`
	QUICKeepAlive         bool     `long:"quic-keep-alive" description:"QUIC keep-alive"`
	QUICNoPMTUD           bool     `long:"quic-no-pmtud" description:"Disable QUIC PMTU discovery"`
	QUICDialTimeout       uint16   `long:"quic-dial-timeout" description:"QUIC dial timeout" default:"10"`
	QUICOpenStreamTimeout uint16   `long:"quic-idle-timeout" description:"QUIC stream open timeout" default:"10"`

	HandshakeTimeout uint16 `long:"handshake-timeout" description:"Handshake timeout" default:"10"`

	UDPBuffer   uint16 `long:"udp-buffer" description:"Set EDNS0 UDP size in query" default:"4096"`
	Verbose     bool   `short:"v" long:"verbose" description:"Show verbose log messages"`
	ShowVersion bool   `short:"V" long:"version" description:"Show version and exit"`
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
}

// tlsVersion returns a TLS version number by given protocol string
func tlsVersion(version string, fallback uint16) uint16 {
	switch version {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return fallback
	}
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

// driver is the "main" function for this program that accepts a flag slice for testing
func driver(args []string) error {
	parser := flags.NewParser(&opts, flags.Default)
	parser.Usage = `[OPTIONS] [@server] [type...] [name]

All long form (--) flags can be toggled with the dig-standard +[no]flag notation.`
	_, err := parser.ParseArgs(args)
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
		if opts.Name == "" {
			rrTypes[dns.StringToType["NS"]] = true
		} else {
			for _, defaultRRType := range []string{"A", "AAAA", "NS", "MX", "TXT", "CNAME"} {
				rrType, _ := dns.StringToType[defaultRRType]
				rrTypes[rrType] = true
			}
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

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.TLSNoVerify,
		MinVersion:         tlsVersion(opts.TLSMinVersion, tls.VersionTLS10),
		MaxVersion:         tlsVersion(opts.TLSMaxVersion, tls.VersionTLS13),
	}

	var rrTypesSlice []uint16
	for rrType := range rrTypes {
		rrTypesSlice = append(rrTypesSlice, rrType)
	}
	msgs := createQuery(
		opts.Name,
		opts.Chaos, opts.DNSSEC, opts.NSID,
		rrTypesSlice,
		opts.AuthoritativeAnswer, opts.AuthenticData, opts.CheckingDisabled, opts.RecursionDesired, opts.RecursionAvailable, opts.Zero,
		opts.UDPBuffer,
		opts.ClientSubnet,
		opts.Pad,
	)
	var replies []*dns.Msg

	// Parse server as URL
	if !strings.Contains(opts.Server, "://") {
		opts.Server = "plain://" + opts.Server
	}
	a, err := url.Parse(opts.Server)
	if err != nil {
		return fmt.Errorf("invalid server URL: %s", err)
	}

	if opts.ODoHProxy != "" && !strings.HasPrefix(opts.ODoHProxy, "https://") {
		return fmt.Errorf("ODoH proxy must use HTTPS")
	}
	if opts.ODoHProxy != "" && a.Scheme != "https" {
		return fmt.Errorf("ODoH target must use HTTPS")
	}

	if (a.Scheme == "http" || a.Scheme == "https") && a.Path == "" {
		a.Path = "/dns-query"
	} else if a.Scheme == "quic" && a.Port() == "" {
		a.Host += ":8853"
	} else if a.Scheme == "tls" && a.Port() == "" {
		a.Host += ":853"
	} else if a.Port() == "" && a.Port() == "" {
		a.Host += ":53"
	}

	if a.Scheme == "quic" {
		tlsConfig.NextProtos = opts.QUICALPNTokens
	}

	log.Debugf("Server: %s", a.String())

	startTime := time.Now()
	switch a.Scheme {
	case "https", "http":
		if opts.ODoHProxy != "" {
			log.Debugf("Using ODoH transport with proxy %s", opts.ODoHProxy)
			for _, msg := range msgs {
				reply, err := transport.ODoH(msg, a.Host, opts.ODoHProxy)
				if err != nil {
					return fmt.Errorf("ODoH query: %s", err)
				}
				replies = append(replies, reply)
			}
		} else {
			log.Debug("Using HTTP(s) transport")
			for _, msg := range msgs {
				reply, err := transport.HTTP(&msg, tlsConfig, a.String(), opts.HTTPUserAgent, opts.HTTPMethod,
					time.Duration(opts.Timeout)*time.Second, time.Duration(opts.HandshakeTimeout)*time.Second)
				if err != nil {
					return err
				}
				replies = append(replies, reply)
			}
		}
	case "quic":
		log.Debug("Using QUIC transport")
		for _, msg := range msgs {
			reply, err := transport.QUIC(&msg, a.Host, tlsConfig,
				time.Duration(opts.QUICDialTimeout)*time.Second,
				time.Duration(opts.HandshakeTimeout)*time.Second,
				time.Duration(opts.QUICOpenStreamTimeout)*time.Second,
				opts.QUICNoPMTUD, opts.QUICKeepAlive)
			if err != nil {
				return err
			}
			replies = append(replies, reply)
		}
	case "tls":
		log.Debug("Using TLS transport")
		for _, msg := range msgs {
			reply, err := transport.TLS(&msg, a.Host, tlsConfig, 5*time.Second)
			if err != nil {
				return err
			}
			replies = append(replies, reply)
		}
	case "tcp":
		log.Debug("Using TCP transport")
		for _, msg := range msgs {
			reply, err := transport.Plain(&msg, a.Host, true, time.Duration(opts.Timeout)*time.Second, opts.UDPBuffer)
			if err != nil {
				return err
			}
			replies = append(replies, reply)
		}
	case "plain":
		log.Debug("Using UDP with TCP fallback")
		for _, msg := range msgs {
			reply, err := transport.Plain(&msg, a.Host, false, time.Duration(opts.Timeout)*time.Second, opts.UDPBuffer)
			if err != nil {
				return err
			}
			replies = append(replies, reply)
		}
	default:
		return fmt.Errorf("unknown transport protocol %s", a.Scheme)
	}
	queryTime := time.Since(startTime)

	for i, reply := range replies {
		// Print answers
		switch opts.Format {
		case "pretty":
			for _, a := range reply.Answer {
				fmt.Printf("%s %s %s %s\n",
					color("purple", a.Header().Name),
					color("green", time.Duration(a.Header().Ttl)*time.Second),
					color("magenta", dns.TypeToString[a.Header().Rrtype]),
					strings.TrimSpace(strings.Join(strings.Split(a.String(), dns.TypeToString[a.Header().Rrtype])[1:], "")),
				)
			}
		case "raw":
			fmt.Println(reply.String())
			fmt.Printf(";; Received %d B\n", reply.Len())
			fmt.Printf(";; Time %s\n", time.Now().Format("15:04:05 01-02-2006 MST"))
			fmt.Printf(";; From %s in %s\n", a.String(), queryTime.Round(100*time.Microsecond))

			// Print separator if there is more than one query
			if len(replies) > 0 && i != len(replies)-1 {
				fmt.Printf("\n--\n\n")
			}
		case "json":
			// Marshal answers to JSON
			marshalled, err := json.Marshal(struct {
				Server    string
				QueryTime int64
				Answers   []dns.RR
			}{
				Server:    opts.Server,
				QueryTime: int64(queryTime / time.Millisecond),
				Answers:   reply.Answer,
			})
			if err != nil {
				return err
			}
			fmt.Println(string(marshalled))
		default:
			return fmt.Errorf("invalid output format")
		}
	}

	return nil // nil error
}

func main() {
	clearOpts()
	if err := driver(os.Args); err != nil {
		log.Fatal(err)
	}
}
