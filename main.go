package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const defaultServerVar = "Q_DEFAULT_SERVER"

// CLI flags
type optsTemplate struct {
	Name         string        `short:"q" long:"qname" description:"Query name"`
	Server       string        `short:"s" long:"server" description:"DNS server"`
	Types        []string      `short:"t" long:"type" description:"RR type (e.g. A, AAAA, MX, etc.) or type integer"`
	Reverse      bool          `short:"x" long:"reverse" description:"Reverse lookup"`
	DNSSEC       bool          `short:"d" long:"dnssec" description:"Set the DO (DNSSEC OK) bit in the OPT record"`
	NSID         bool          `short:"n" long:"nsid" description:"Set EDNS0 NSID opt"`
	ClientSubnet string        `long:"subnet" description:"Set EDNS0 client subnet"`
	Chaos        bool          `short:"c" long:"chaos" description:"Use CHAOS query class"`
	Class        uint16        `short:"C" description:"Set query class (default: IN 0x01)" default:"1"`
	ODoHProxy    string        `short:"p" long:"odoh-proxy" description:"ODoH proxy"`
	Timeout      time.Duration `long:"timeout" description:"Query timeout" default:"10s"`
	Pad          bool          `long:"pad" description:"Set EDNS0 padding"`
	HTTP3        bool          `long:"http3" description:"Use HTTP/3 for DoH"`
	NoIDCheck    bool          `long:"no-id-check" description:"Disable checking of DNS response ID"`

	RecAXFR bool `long:"recaxfr" description:"Perform recursive AXFR"`

	// Output
	Format         string `short:"f" long:"format" description:"Output format (pretty, json, yaml, raw)" default:"pretty"`
	PrettyTTLs     bool   `long:"pretty-ttls" description:"Format TTLs in human readable format (default: true)"`
	Color          bool   `long:"color" description:"Enable color output"`
	ShowQuestion   bool   `long:"question" description:"Show question section"`
	ShowAnswer     bool   `long:"answer" description:"Show answer section (default: true)"`
	ShowAuthority  bool   `long:"authority" description:"Show authority section"`
	ShowAdditional bool   `long:"additional" description:"Show additional section"`
	ShowStats      bool   `short:"S" long:"stats" description:"Show time statistics"`
	ShowAll        bool   `long:"all" description:"Show all sections and statistics"`
	Whois          bool   `short:"w" description:"Resolve ASN/ASName for A and AAAA records"`
	ValueOnly      bool   `short:"r" long:"value" description:"Show record values only"`

	// Header flags
	AuthoritativeAnswer bool `long:"aa" description:"Set AA (Authoritative Answer) flag in query"`
	AuthenticData       bool `long:"ad" description:"Set AD (Authentic Data) flag in query"`
	CheckingDisabled    bool `long:"cd" description:"Set CD (Checking Disabled) flag in query"`
	RecursionDesired    bool `long:"rd" description:"Set RD (Recursion Desired) flag in query (default: true)"`
	RecursionAvailable  bool `long:"ra" description:"Set RA (Recursion Available) flag in query"`
	Zero                bool `long:"z" description:"Set Z (Zero) flag in query"`
	Truncated           bool `long:"t" description:"Set TC (Truncated) flag in query"`

	// TCP parameters
	TLSNoVerify     bool     `short:"i" long:"tls-no-verify" description:"Disable TLS certificate verification"`
	TLSServerName   string   `long:"tls-server-name" description:"TLS server name for host verification"`
	TLSMinVersion   string   `long:"tls-min-version" description:"Minimum TLS version to use" default:"1.0"`
	TLSMaxVersion   string   `long:"tls-max-version" description:"Maximum TLS version to use" default:"1.3"`
	TLSNextProtos   []string `long:"tls-next-protos" description:"TLS next protocols for ALPN"`
	TLSCipherSuites []string `long:"tls-cipher-suites" description:"TLS cipher suites"`

	// HTTP
	HTTPUserAgent string `long:"http-user-agent" description:"HTTP user agent" default:""`
	HTTPMethod    string `long:"http-method" description:"HTTP method" default:"GET"`

	// QUIC
	QUICALPNTokens     []string `long:"quic-alpn-tokens" description:"QUIC ALPN tokens" default:"doq" default:"doq-i11"`
	QUICNoPMTUD        bool     `long:"quic-no-pmtud" description:"Disable QUIC PMTU discovery"`
	QUICNoLengthPrefix bool     `long:"quic-no-length-prefix" description:"Don't add RFC 9250 compliant length prefix"`

	DefaultRRTypes []string `long:"default-rr-types" description:"Default record types" default:"A" default:"AAAA" default:"NS" default:"MX" default:"TXT" default:"CNAME"`

	UDPBuffer   uint16 `long:"udp-buffer" description:"Set EDNS0 UDP size in query" default:"1232"`
	Verbose     bool   `short:"v" long:"verbose" description:"Show verbose log messages"`
	Trace       bool   `long:"trace" description:"Show trace log messages"`
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

var tlsCipherSuiteToInt = map[string]uint16{
	// TLS 1.0 - 1.2
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

	// TLS 1.3
	"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
}

// parseTLSCipherSuites converts a slice of cipher suite names to a slice of cipher suite ints
func parseTLSCipherSuites(cipherSuites []string) []uint16 {
	var cipherSuiteInts []uint16
	for _, cipherSuite := range cipherSuites {
		if cipherSuiteInt, ok := tlsCipherSuiteToInt[cipherSuite]; ok {
			cipherSuiteInts = append(cipherSuiteInts, cipherSuiteInt)
		} else {
			log.Fatalf("Unknown TLS cipher suite: %s", cipherSuite)
		}
	}
	return cipherSuiteInts
}

// color returns a color formatted string
func color(color string, args ...interface{}) string {
	if opts.Color {
		return fmt.Sprintf(colors[color], fmt.Sprint(args...))
	} else {
		return fmt.Sprint(args...)
	}
}

// clearOpts sets the default values for the CLI options
func clearOpts() {
	opts = optsTemplate{}
	opts.RecursionDesired = true
	opts.ShowAnswer = true
	opts.PrettyTTLs = true

	// Enable color output if stdout is a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		opts.Color = true
	}

	// Disable color output if NO_COLOR env var is set
	if os.Getenv("NO_COLOR") != "" {
		log.Debug("NO_COLOR set")
		opts.Color = false
	}
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

// parseServer parses opts.Server into a protocol and host:port
func parseServer() (string, string, error) {
	var scheme, host, port, scopeId string

	// Set default protocol
	if !strings.Contains(opts.Server, "://") {
		scheme = "plain"
	} else {
		scheme = strings.Split(opts.Server, "://")[0]
	}

	// Parse DNS stamp
	if strings.HasPrefix(opts.Server, "sdns://") {
		parsedStamp, err := dnsstamps.NewServerStampFromString(opts.Server)
		if err != nil {
			return "", "", err
		}

		switch parsedStamp.Proto {
		case dnsstamps.StampProtoTypePlain:
			scheme = "plain"
		case dnsstamps.StampProtoTypeTLS:
			scheme = "tls"
		case dnsstamps.StampProtoTypeDoH:
			scheme = "https"
		default:
			return "", "", fmt.Errorf("unsupported protocol %s in DNS stamp", parsedStamp.Proto.String())
		}

		host = parsedStamp.ProviderName
	} else { // Not DNS stamp
		// Server without port or protocol
		host = strings.ReplaceAll(opts.Server, scheme+"://", "")

		// Remove port from host
		if strings.Contains(host, "[") && !strings.Contains(host, "]") || !strings.Contains(host, "[") && strings.Contains(host, "]") {
			return "", "", fmt.Errorf("invalid IPv6 bracket notation")
		} else if strings.Contains(host, "[") && strings.Contains(host, "]") { // IPv6 in bracket notation
			portSuffix := strings.Split(host, "]:")
			if len(portSuffix) > 1 { // With explicit port
				port = portSuffix[1]
			} else {
				port = ""
			}

			host = strings.Split(strings.Split(host, "[")[1], "]")[0]

			// Remove IPv6 scope ID
			if strings.Contains(host, "%") {
				parts := strings.Split(host, "%")
				host = parts[0]
				scopeId = parts[1]
			}

			host = "[" + host + "]"
			log.Tracef("host contains ], treating as v6 with port. host: %s port: %s", host, port)
		} else if strings.Contains(host, ".") && strings.Contains(host, ":") { // IPv4 or hostname with port
			parts := strings.Split(host, ":")
			host = parts[0]
			port = parts[1]
			log.Tracef("host contains . and :, treating as (v4 or host) with explicit port. host %s port %s", host, port)
		} else if strings.Contains(host, ":") { // IPv6 no port
			// Remove IPv6 scope ID
			if strings.Contains(host, "%") {
				parts := strings.Split(host, "%")
				host = parts[0]
				scopeId = parts[1]
			}

			host = "[" + host + "]"
			log.Tracef("host contains :, treating as v6 without port. host %s", host)
		} else {
			log.Tracef("no cases matched for host %s port %s", host, port)
		}
	}

	// Validate ODoH
	if opts.ODoHProxy != "" {
		if !strings.HasPrefix(opts.ODoHProxy, "https://") {
			return "", "", fmt.Errorf("ODoH proxy must use HTTPS")
		}
		if scheme != "https" {
			return "", "", fmt.Errorf("ODoH target must use HTTPS")
		}
	}

	if port == "" {
		switch scheme {
		case "quic":
			port = "853"
		case "tls":
			port = "853"
		case "https":
			port = "443"
		default:
			port = "53"
		}
		log.Tracef("Setting port to %s", port)
	} else {
		log.Tracef("Port is %s, not overriding", port)
	}

	fqdn := scheme + "://" + host
	if scheme != "https" {
		fqdn += ":" + port
	}
	log.Tracef("checking FQDN %s", fqdn)
	u, err := url.Parse(fqdn)
	if err != nil {
		return "", "", err
	}

	server := host + ":" + port

	if scheme == "https" {
		port = strings.Split(port, "/")[0]
		u.Host += ":" + port
		server = u.String()

		// Add default path if missing
		if u.Path == "" {
			server += "/dns-query"
			log.Tracef("HTTPS scheme and no path, setting server to %s", server)
		}
	}

	// Insert scope ID before ']'
	if scopeId != "" {
		server = strings.Replace(server, "]", "%"+scopeId+"]", 1)
	}

	return scheme, server, nil
}

// driver is the "main" function for this program that accepts a flag slice for testing
func driver(args []string, out io.Writer) error {
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

	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	} else if opts.Trace {
		log.SetLevel(log.TraceLevel)
	}

	if opts.ShowVersion {
		mustWritef(out, "https://github.com/natesales/q version %s (%s %s)\n", version, commit, date)
		return nil
	}

	if opts.ShowAll {
		opts.ShowQuestion = true
		opts.ShowAnswer = true
		opts.ShowAuthority = true
		opts.ShowAdditional = true
		opts.ShowStats = true
	}

	// Parse requested RR types
	rrTypes := make(map[uint16]bool)
	for _, rrType := range opts.Types {
		typeCode, ok := dns.StringToType[strings.ToUpper(rrType)]
		if ok {
			rrTypes[typeCode] = true
		} else {
			typeCode, err := strconv.Atoi(rrType)
			if err != nil {
				return fmt.Errorf("%s is not a valid RR type", rrType)
			}
			log.Debugf("using RR type %d as integer", typeCode)
			rrTypes[uint16(typeCode)] = true
		}
	}

	// Add non-flag RR types
	for _, arg := range args {
		// Find a server by @ symbol if it isn't set by flag
		if opts.Server == "" && strings.HasPrefix(arg, "@") {
			opts.Server = strings.TrimPrefix(arg, "@")
		}

		// Parse chaos class
		if strings.ToLower(arg) == "ch" {
			opts.Chaos = true
		}

		// Add non-flag RR types
		rrType, typeFound := dns.StringToType[strings.ToUpper(arg)]
		if typeFound {
			rrTypes[rrType] = true
		}

		// Set qname if not set by flag
		if opts.Name == "" &&
			!containsAny(arg, []string{"@", "/", "\\", "+"}) && // Not a server, path, or flag
			!typeFound && // Not a RR type
			!strings.HasSuffix(arg, ".exe") && // Not an executable
			!strings.HasPrefix(arg, "-") { // Not a flag
			opts.Name = arg
		}
	}

	// If no RR types are defined, set a list of default ones
	if len(rrTypes) < 1 {
		if opts.Name == "" {
			rrTypes[dns.StringToType["NS"]] = true
		} else {
			for _, defaultRRType := range opts.DefaultRRTypes {
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
		log.Debugf("Name: %s", opts.Name)
		var rrTypeStrings []string
		for rrType := range rrTypes {
			rrTypeStrings = append(rrTypeStrings, dns.TypeToString[rrType])
		}
		log.Debugf("RR types: %+v", rrTypeStrings)
	}

	// Set default DNS server
	if opts.Server == "" {
		if os.Getenv(defaultServerVar) != "" {
			opts.Server = os.Getenv(defaultServerVar)
			log.Debugf("Using %s from %s environment variable", opts.Server, defaultServerVar)
		} else {
			log.Debugf("No server specified or %s set, using /etc/resolv.conf", defaultServerVar)
			conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				opts.Server = "https://cloudflare-dns.com/dns-query"
				log.Debugf("no server set, using %s", opts.Server)
			} else {
				if len(conf.Servers) == 0 {
					opts.Server = "https://cloudflare-dns.com/dns-query"
					log.Debugf("no server set, using %s", opts.Server)
				} else {
					opts.Server = conf.Servers[0]
					log.Debugf("found server %s from /etc/resolv.conf", opts.Server)
				}
			}
		}
	}

	if opts.Chaos {
		log.Debug("Flag set, using chaos class")
		opts.Class = dns.ClassCHAOS
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.TLSNoVerify,
		ServerName:         opts.TLSServerName,
		MinVersion:         tlsVersion(opts.TLSMinVersion, tls.VersionTLS10),
		MaxVersion:         tlsVersion(opts.TLSMaxVersion, tls.VersionTLS13),
		NextProtos:         opts.TLSNextProtos,
		CipherSuites:       parseTLSCipherSuites(opts.TLSCipherSuites),
	}

	if klf := os.Getenv("SSLKEYLOGFILE"); klf != "" {
		log.Warnf("SSLKEYLOGFILE is set! TLS master secrets will be logged.")
		keyLog, err := os.OpenFile(klf, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("unable to open SSLKEYLOGFILE: %s %s", klf, err)
		}
		tlsConfig.KeyLogWriter = keyLog
	}

	var rrTypesSlice []uint16
	for rrType := range rrTypes {
		rrTypesSlice = append(rrTypesSlice, rrType)
	}
	msgs := createQuery(
		opts.Name,
		opts.DNSSEC, opts.NSID,
		opts.Class,
		rrTypesSlice,
		opts.AuthoritativeAnswer, opts.AuthenticData, opts.CheckingDisabled, opts.RecursionDesired, opts.RecursionAvailable, opts.Zero, opts.Truncated,
		opts.UDPBuffer,
		opts.ClientSubnet,
		opts.Pad,
	)

	protocol, server, err := parseServer()
	if err != nil {
		return err
	}

	if protocol == "quic" {
		tlsConfig.NextProtos = opts.QUICALPNTokens
	}

	if opts.RecAXFR {
		if opts.Name == "" {
			return fmt.Errorf("no name specified for AXFR")
		}
		_ = RecAXFR(opts.Name, server, out)
		return nil
	}

	startTime := time.Now()
	var replies []*dns.Msg
	for _, msg := range msgs {
		reply, err := query(msg, server, protocol, tlsConfig)
		if err != nil {
			return err
		}

		// Skip ID check if QUIC (https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1)
		if protocol != "quic" && !opts.NoIDCheck && reply.Id != msg.Id {
			return fmt.Errorf("ID mismatch: expected %d, got %d", msg.Id, reply.Id)
		}
		replies = append(replies, reply)
	}
	queryTime := time.Since(startTime)

	return display(replies, server, queryTime, out)
}

func main() {
	clearOpts()
	if err := driver(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
