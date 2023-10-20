package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/output"
	"github.com/natesales/q/transport"
	"github.com/natesales/q/util"
)

const defaultServerVar = "Q_DEFAULT_SERVER"

var opts = cli.Flags{}

// Build process flags
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

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

// clearOpts sets the default values for the CLI options
func clearOpts() {
	opts = cli.Flags{}
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
	util.UseColor = opts.Color
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

func txtConcat(m *dns.Msg) {
	var answers []dns.RR
	for _, answer := range m.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			txt := answer.(*dns.TXT)

			// Concat TXT responses if requested
			if opts.TXTConcat {
				log.Debugf("Concatenating TXT response: %+v", txt.Txt)
				txt.Txt = []string{strings.Join(txt.Txt, "")}
			}
			answers = append(answers, txt)
		} else {
			answers = append(answers, answer)
		}
	}
	m.Answer = answers
}

// parseServer parses opts.Server and returns the server address and transport type
func parseServer() (string, transport.Type, error) {
	var txp transport.Type
	var host, port, scopeId string
	var isHTTPS bool

	// Set default protocol
	if !strings.Contains(opts.Server, "://") {
		txp = transport.TypePlain
	} else {
		txp = transport.Type(strings.Split(opts.Server, "://")[0])
		if txp == "https" {
			isHTTPS = true
			txp = transport.TypeHTTP
		}
	}

	// Parse DNS stamp
	if strings.HasPrefix(opts.Server, "sdns://") {
		parsedStamp, err := dnsstamps.NewServerStampFromString(opts.Server)
		if err != nil {
			return "", "", err
		}

		switch parsedStamp.Proto {
		case dnsstamps.StampProtoTypePlain:
			txp = transport.TypePlain
		case dnsstamps.StampProtoTypeTLS:
			txp = transport.TypeTLS
		case dnsstamps.StampProtoTypeDoH:
			isHTTPS = true // Default to DoH (HTTPS)
			txp = transport.TypeHTTP
		case dnsstamps.StampProtoTypeDNSCrypt:
			// DNS stamp parsing happens again in the DNSCrypt transport
			return opts.Server, transport.TypeDNSCrypt, nil
		default:
			return "", "", fmt.Errorf("unsupported protocol %s in DNS stamp", parsedStamp.Proto.String())
		}
		log.Tracef("DNS stamp parsed as %s", txp)

		// TODO: This might be a source of problems...we might want to be using parsedStamp.ServerAddrStr
		host = parsedStamp.ProviderName
	} else { // Not DNS stamp
		// Remove anything before and including the first ://
		host = regexp.MustCompile(`^.*://`).ReplaceAllString(opts.Server, "")

		// Remove port from host
		switch {
		case strings.Contains(host, "[") && !strings.Contains(host, "]") ||
			!strings.Contains(host, "[") && strings.Contains(host, "]"):
			return "", "", fmt.Errorf("invalid IPv6 bracket notation")
		case strings.Contains(host, "[") && strings.Contains(host, "]"): // IPv6 in bracket notation
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
		case strings.Contains(host, ".") && strings.Contains(host, ":"): // IPv4 or hostname with port
			parts := strings.Split(host, ":")
			host = parts[0]
			port = parts[1]
			log.Tracef("host contains . and :, treating as (v4 or host) with explicit port. host %s port %s", host, port)
		case strings.Contains(host, ":") && !strings.Contains(host, "/"): // IPv6 no port
			// Remove IPv6 scope ID
			if strings.Contains(host, "%") {
				parts := strings.Split(host, "%")
				host = parts[0]
				scopeId = parts[1]
			}

			host = "[" + host + "]"
			log.Tracef("host contains :, treating as v6 without port. host %s", host)
		default:
			log.Tracef("no cases matched for host %s port %s", host, port)
		}
	}

	// Validate ODoH
	if opts.ODoHProxy != "" {
		if !strings.HasPrefix(opts.ODoHProxy, "https://") {
			return "", "", fmt.Errorf("ODoH proxy must use HTTPS")
		}
		if !strings.HasPrefix(opts.Server, "https://") {
			return "", "", fmt.Errorf("ODoH target must use HTTPS")
		}
	}

	if port == "" {
		switch txp {
		case transport.TypeQUIC:
			port = "853"
		case transport.TypeTLS:
			port = "853"
		case transport.TypeHTTP:
			if isHTTPS {
				port = "443"
			} else {
				port = "80"
			}
		case transport.TypePlain:
			port = "53"
		}
		log.Tracef("Setting port to %s", port)
	} else {
		log.Tracef("Port is %s, not overriding", port)
	}

	urlScheme := string(txp)
	if isHTTPS {
		urlScheme = "https"
	}

	fqdn := urlScheme + "://" + host
	if txp != transport.TypeHTTP {
		fqdn += ":" + port
	}
	log.Tracef("checking FQDN %s", fqdn)
	u, err := url.Parse(fqdn)
	if err != nil {
		return "", "", err
	}

	server := host + ":" + port

	if txp == transport.TypeHTTP {
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

	return server, txp, nil
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
	util.UseColor = opts.Color

	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	} else if opts.Trace {
		log.SetLevel(log.TraceLevel)
		opts.ShowAll = true
	}

	if opts.ShowVersion {
		util.MustWritef(out, "https://github.com/natesales/q version %s (%s %s)\n", version, commit, date)
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
			!util.ContainsAny(arg, []string{"@", "/", "\\", "+"}) && // Not a server, path, or flag
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
				rrTypes[dns.StringToType[defaultRRType]] = true
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

	// TLS client certificate authentication
	if opts.TLSClientCertificate != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSClientCertificate, opts.TLSClientKey)
		if err != nil {
			return fmt.Errorf("unable to load client certificate: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// TLS secret logging
	if opts.TLSKeyLogFile != "" {
		log.Warnf("TLS secret logging enabled")
		keyLogFile, err := os.OpenFile(opts.TLSKeyLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("unable to open TLS key log file: %s", err)
		}
		tlsConfig.KeyLogWriter = keyLogFile
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

	server, transportType, err := parseServer()
	if err != nil {
		return err
	}

	if transportType == transport.TypeQUIC {
		tlsConfig.NextProtos = opts.QUICALPNTokens
		// Skip ID check if QUIC (https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1)
		opts.NoIDCheck = true
	}

	if opts.RecAXFR {
		if opts.Name == "" {
			return fmt.Errorf("no name specified for AXFR")
		}
		_ = RecAXFR(opts.Name, server, out)
		return nil
	}

	// Create transport
	txp, err := newTransport(server, transportType, tlsConfig)
	if err != nil {
		return err
	}

	startTime := time.Now()
	var replies []*dns.Msg
	for _, msg := range msgs {
		reply, err := (*txp).Exchange(&msg)
		if err != nil {
			return err
		}

		if !opts.NoIDCheck && reply.Id != msg.Id {
			return fmt.Errorf("ID mismatch: expected %d, got %d", msg.Id, reply.Id)
		}
		replies = append(replies, reply)
	}
	queryTime := time.Since(startTime)

	// Process TXT parsing
	if opts.TXTConcat {
		for _, reply := range replies {
			txtConcat(reply)
		}
	}

	if opts.NSID && opts.Format == "pretty" {
		output.PrettyPrintNSID(replies, out)
	}

	printer := output.Printer{
		Server:     server,
		Out:        out,
		Opts:       &opts,
		QueryTime:  queryTime,
		NumReplies: len(replies),
		Transport:  txp,
	}
	for i, reply := range replies {
		switch opts.Format {
		case "pretty":
			printer.PrintPretty(i, reply)
		case "raw":
			printer.PrintRaw(i, reply)
		case "json", "yml", "yaml":
			printer.PrintStructured(i, reply)
		default:
			return fmt.Errorf("invalid output format")
		}
	}

	return nil
}

func main() {
	clearOpts()
	if err := driver(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
