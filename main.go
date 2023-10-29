package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
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
	tlsutil "github.com/natesales/q/util/tls"
)

const defaultServerVar = "Q_DEFAULT_SERVER"

var opts = cli.Flags{}

// Build process flags
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// clearOpts sets the default values for the CLI options
func clearOpts() {
	opts = cli.Flags{}
	opts.RecursionDesired = true
	opts.ShowAnswer = true
	opts.PrettyTTLs = true
	opts.ShortTTLs = true

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

// dnsStampToURL converts a DNS stamp string to a URL string
func dnsStampToURL(s string) (string, error) {
	var u url.URL

	parsedStamp, err := dnsstamps.NewServerStampFromString(s)
	if err != nil {
		return "", err
	}

	switch parsedStamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		u.Scheme = string(transport.TypePlain)
	case dnsstamps.StampProtoTypeTLS:
		u.Scheme = string(transport.TypeTLS)
	case dnsstamps.StampProtoTypeDoH:
		u.Scheme = string(transport.TypeHTTP) + "s" // default to HTTPS
	case dnsstamps.StampProtoTypeDNSCrypt:
		// DNS stamp parsing happens again in the DNSCrypt transport, so pass the input along unchanged
		return s, nil
	default:
		return "", fmt.Errorf("unsupported protocol %s in DNS stamp", parsedStamp.Proto.String())
	}

	// TODO: This might be a source of problems...we might want to be using parsedStamp.ServerAddrStr
	u.Host = parsedStamp.ProviderName

	log.Tracef("DNS stamp parsed into URL as %s", u.String())
	return u.String(), nil
}

// setPort sets the port of a url.URL
func setPort(u *url.URL, port int) {
	if strings.Contains(u.Host, ":") {
		if strings.Contains(u.Host, "[") && strings.Contains(u.Host, "]") {
			u.Host = fmt.Sprintf("%s]:%d", strings.Split(u.Host, "]")[0], port)
			return
		}
		u.Host = "[" + u.Host + "]"
	}
	u.Host = fmt.Sprintf("%s:%d", u.Host, port)
}

// parseServer is a revised version of parseServer that uses the URL package for parsing
func parseServer(s string) (string, transport.Type, error) {
	// Remove IPv6 scope ID if present
	var scopeId string
	v6scopeRe := regexp.MustCompile(`\[[a-fA-F0-9:]+%[a-zA-Z0-9]+]`)
	if v6scopeRe.MatchString(s) {
		v6scopeRemoveRe := regexp.MustCompile(`(%[a-zA-Z0-9]+)`)
		matches := v6scopeRemoveRe.FindStringSubmatch(s)
		if len(matches) > 1 {
			scopeId = matches[1]
			s = v6scopeRemoveRe.ReplaceAllString(s, "")
		}
		log.Tracef("Removed IPv6 scope ID %s from server %s", scopeId, s)
	}

	// Handle DNS stamp
	if strings.HasPrefix(s, "sdns://") {
		var err error
		s, err = dnsStampToURL(s)
		if err != nil {
			return "", "", fmt.Errorf("converting DNS stamp to URL: %s", err)
		}
		// If s is still a DNS stamp, it's DNSCrypt
		if strings.HasPrefix(s, "sdns://") {
			return s, transport.TypeDNSCrypt, nil
		}
	}

	// Check if server starts with a scheme, if not, default to plain
	schemeRe := regexp.MustCompile(`^[a-zA-Z0-9]+://`)
	if !schemeRe.MatchString(s) {
		s = "plain://" + s
	}

	// Parse server as URL
	tu, err := url.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("parsing %s: %s", s, err)
	}

	// Parse transport type
	ts := transport.Type(tu.Scheme)
	if tu.Scheme == "https" { // Override HTTPS to HTTP, preserving tu.Scheme as HTTPS
		ts = transport.TypeHTTP
	}
	if !slices.Contains(transport.Types, ts) {
		return "", "", fmt.Errorf("unsupported transport %s. expected: %+v", ts, transport.Types)
	}

	// Set default port
	if tu.Port() == "" {
		switch ts {
		case transport.TypeQUIC, transport.TypeTLS:
			setPort(tu, 853)
		case transport.TypeHTTP:
			if tu.Scheme == "https" {
				setPort(tu, 443)
			} else {
				setPort(tu, 80)
			}
		case transport.TypePlain, transport.TypeTCP:
			setPort(tu, 53)
		}
	}

	// Add default path if missing
	if ts == transport.TypeHTTP && tu.Path == "" {
		tu.Path = "/dns-query"
	}

	server := tu.String()
	// Remove scheme from server if irrelevant to protocol
	if ts != transport.TypeHTTP {
		server = strings.Split(server, "://")[1]
	}

	// Add IPv6 scope ID back to server
	if scopeId != "" {
		server = strings.Replace(server, "]", scopeId+"]", 1)
	}

	return server, ts, nil
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

	// Validate ODoH
	if opts.ODoHProxy != "" {
		if !strings.HasPrefix(opts.ODoHProxy, "https://") {
			return fmt.Errorf("ODoH proxy must use HTTPS")
		}
		if !strings.HasPrefix(opts.Server, "https://") {
			return fmt.Errorf("ODoH target must use HTTPS")
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
		MinVersion:         tlsutil.Version(opts.TLSMinVersion, tls.VersionTLS10),
		MaxVersion:         tlsutil.Version(opts.TLSMaxVersion, tls.VersionTLS13),
		NextProtos:         opts.TLSNextProtos,
		CipherSuites:       tlsutil.ParseCipherSuites(opts.TLSCipherSuites),
		CurvePreferences:   tlsutil.ParseCurves(opts.TLSCurvePreferences),
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
		opts.ID,
	)

	// Parse server address and transport type
	server, transportType, err := parseServer(opts.Server)
	if err != nil {
		return err
	}
	log.Debugf("Using server %s with transport %s", server, transportType)

	// QUIC specific overrides
	if transportType == transport.TypeQUIC {
		tlsConfig.NextProtos = opts.QUICALPNTokens
		// Skip ID check if QUIC (https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1)
		opts.NoIDCheck = true
	}

	// Recursive zone transfer
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
	if opts.Format == "column" {
		printer.PrintColumn(replies)
	} else {
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
	}

	return nil
}

func main() {
	clearOpts()
	if err := driver(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
