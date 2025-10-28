package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/idna"

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
	cli.SetDefaultTrueBools(&opts)

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
	u.Path = parsedStamp.Path

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
	v6scopeRe := regexp.MustCompile(`(^|\[)[a-fA-F0-9:]+%[a-zA-Z0-9]+`)
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
		// Enclose in brackets if IPv6
		v6re := regexp.MustCompile(`^[a-fA-F0-9:]+$`)
		if v6re.MatchString(s) {
			s = "[" + s + "]"
		}
		s = "plain://" + s
	}

	// Parse server as URL
	tu, err := url.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("parsing %s as URL: %s", s, err)
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
	args = cli.SetFalseBooleans(&opts, args)
	args = cli.AddEqualSigns(args)
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
	cli.ParsePlusFlags(&opts, args)
	util.UseColor = opts.Color

	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	} else if opts.Trace || opts.Recursive {
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

	// Set bootstrap resolver
	if opts.BootstrapServer != "" {
		// Add port if not specified
		rePortSuffix := regexp.MustCompile(`:\d+$`)
		if !rePortSuffix.MatchString(opts.BootstrapServer) {
			opts.BootstrapServer += ":53"
		}

		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: opts.BootstrapTimeout}
				return d.DialContext(ctx, network, opts.BootstrapServer)
			},
		}

		log.Debugf("Using bootstrap resolver %s", opts.BootstrapServer)
	}

	// Parse requested RR types
	rrTypes, err := cli.ParseRRTypes(opts.Types)
	if err != nil {
		return err
	}

	// Add non-flag RR types
	for _, arg := range args {
		// Find a server by @ symbol if it isn't set by flag
		if strings.HasPrefix(arg, "@") {
			opts.Server = append(opts.Server, strings.TrimPrefix(arg, "@"))
		}

		// Parse chaos class
		if strings.ToLower(arg) == "ch" {
			opts.Chaos = true
		}

		// Add non-flag RR types
		rrType, typeFound := dns.StringToType[strings.ToUpper(arg)]
		if typeFound {
			rrTypes[rrType] = true
			if rrType == dns.TypeNS {
				opts.ShowAuthority = true
				opts.ShowAdditional = true
			}
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

	// IDNA (punycode) normalize non-ASCII domain names unless reverse lookup
	if opts.Name != "" && !opts.Reverse {
		// Skip if already an in-addr.arpa or ip6.arpa name
		lowerName := strings.ToLower(opts.Name)
		if !strings.HasSuffix(lowerName, ".in-addr.arpa") && !strings.HasSuffix(lowerName, ".ip6.arpa") {
			// Allow underscores during IDNA conversion
			_asciiName := strings.ReplaceAll(opts.Name, "_", "..")
			asciiName, err := idna.Lookup.ToASCII(_asciiName)
			if err != nil {
				return fmt.Errorf("idna toascii: %s", err)
			}
			opts.Name = strings.ReplaceAll(asciiName, "..", "_")
		}
	}

	// Log RR types
	if opts.Verbose {
		log.Debugf("Name: %s", opts.Name)
		var rrTypeStrings []string
		for rrType := range rrTypes {
			rrS, ok := dns.TypeToString[rrType]
			if !ok {
				rrS = fmt.Sprintf("TYPE%d", rrType)
			}
			rrTypeStrings = append(rrTypeStrings, rrS)
		}
		log.Debugf("RR types: %+v", rrTypeStrings)
	}

	// Set default DNS server
	if len(opts.Server) == 0 {
		opts.Server = make([]string, 1)

		if opts.Recursive {
			if err = initRootServer(); err != nil {
				return err
			}
		} else if os.Getenv(defaultServerVar) != "" {
			opts.Server[0] = os.Getenv(defaultServerVar)
			log.Debugf("Using %s from %s environment variable", opts.Server, defaultServerVar)
		} else {
			log.Debugf("No server specified or %s set, using /etc/resolv.conf", defaultServerVar)
			conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				opts.Server[0] = "https://cloudflare-dns.com/dns-query"
				log.Debugf("no server set, using %s", opts.Server)
			} else {
				if len(conf.Servers) == 0 {
					opts.Server[0] = "https://cloudflare-dns.com/dns-query"
					log.Debugf("no server set, using %s", opts.Server)
				} else {
					opts.Server[0] = conf.Servers[0]
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
		for _, server := range opts.Server {
			if !strings.HasPrefix(server, "https://") {
				return fmt.Errorf("ODoH target must use HTTPS")
			}
		}
	}

	log.Debugf("Server(s): %s", opts.Server)

	if opts.Chaos {
		log.Debug("Flag set, using chaos class")
		opts.Class = dns.ClassCHAOS
	}

	if opts.NSIDOnly {
		opts.NSID = true
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.TLSInsecureSkipVerify,
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
	msgs := createQuery(opts, rrTypesSlice)

	if opts.Recursive {
		if len(msgs) > 1 {
			return fmt.Errorf("Only query one type in recursive mode")
		}

		opts.Timeout = 10 * time.Minute // FIXME(tao)
	}

	errChan := make(chan error)

	servers := opts.Server

	go func() {
	recursive:
		var replies []*dns.Msg
		var entries []*output.Entry
		for _, serverStr := range servers {
			// Parse server address and transport type
			server, transportType, err := parseServer(serverStr)
			if err != nil {
				errChan <- fmt.Errorf("parsing server %s: %s", serverStr, err)
			}
			log.Debugf("Using server %s with transport %s", server, transportType)

			// Recursive zone transfer
			if opts.RecAXFR {
				if opts.Name == "" {
					errChan <- fmt.Errorf("no name specified for AXFR")
				}
				_ = RecAXFR(opts.Name, server, out)
				errChan <- nil // exit immediately
			}

			// Create transport
			txp, err := newTransport(server, transportType, tlsConfig)
			if err != nil {
				errChan <- fmt.Errorf("creating transport: %s", err)
			}

			startTime := time.Now()
			for _, msg := range msgs {
				if txp == nil {
					errChan <- fmt.Errorf("transport is nil")
				}
				reply, err := (*txp).Exchange(&msg)
				if err != nil {
					errChan <- fmt.Errorf("exchange: %s", err)
				}

				if reply == nil {
					errChan <- fmt.Errorf("no reply from server")
				}

				if opts.ShowOpt {
					for _, o := range reply.Extra {
						if o.Header().Rrtype == dns.TypeOPT {
							fmt.Printf("OPT: %v\n", o)
						}
					}
				}

				if transportType != transport.TypeQUIC && opts.IDCheck && reply.Id != msg.Id {
					errChan <- fmt.Errorf("ID mismatch: expected %d, got %d", msg.Id, reply.Id)
				}
				replies = append(replies, reply)
			}

			// Process TXT parsing
			if opts.TXTConcat {
				for _, reply := range replies {
					txtConcat(reply)
				}
			}

			// Round TTL
			if opts.RoundTTLs {
				for _, reply := range replies {
					for _, rr := range reply.Answer {
						rr.Header().Ttl = rr.Header().Ttl - (rr.Header().Ttl % 60)
					}
				}
			}

			e := &output.Entry{
				Queries: msgs,
				Replies: replies,
				Server:  server,
				Time:    time.Since(startTime),
			}

			if opts.ResolveIPs {
				e.LoadPTRs(txp)
			}

			entries = append(entries, e)

			if err := (*txp).Close(); err != nil {
				errChan <- fmt.Errorf("closing transport: %s", err)
			}
		}

		printer := output.Printer{
			Out:  out,
			Opts: &opts,
		}

		if (opts.NSID && (opts.Format == output.FormatPretty || opts.Format == output.FormatColumn)) || opts.NSIDOnly {
			printer.PrettyPrintNSID(entries, !opts.NSIDOnly)
		}

		// Skip printing if NSIDOnly is set
		if opts.NSIDOnly {
			errChan <- nil
		}

		switch opts.Format {
		case output.FormatPretty:
			printer.PrintPretty(entries)
		case output.FormatColumn:
			printer.PrintColumn(entries)
		case output.FormatRAW:
			printer.PrintRaw(entries)
		case output.FormatJSON, output.FormatYAML, "yml":
			printer.PrintStructured(entries)
		default:
			errChan <- fmt.Errorf("invalid output format %s", opts.Format)
		}

		if opts.Recursive && len(replies) > 0 {
			servers = getRecursiveServers(replies)
			if len(servers) > 0 {
				goto recursive
			}
		}

		errChan <- nil
	}()

	select {
	case <-time.After(opts.Timeout):
		return fmt.Errorf("timeout after %s", opts.Timeout)
	case err := <-errChan:
		return err
	}
}

func initRootServer() error {
	ipv4s, ipv6s, err := getRootHints()
	if err != nil {
		return fmt.Errorf("unable to load root hints: %s", err)
	}

	hasIPv6, err := supportIPv6()
	if err != nil {
		return fmt.Errorf("unable to detect ipv6 support: %s", err)
	}

	if !hasIPv6 {
		opts.ForceIPv4 = true
	}

	if opts.ForceIPv4 {
		opts.Server = ipv4s[:1]
	} else {
		opts.Server = ipv6s[:1]
	}
	return nil
}

func getRecursiveServers(replies []*dns.Msg) (servers []string) {
	if r := replies[0]; len(r.Answer) == 0 {
		servers = []string{}
		if opts.ForceIPv4 {
			for _, extra := range r.Extra {
				if a, ok := extra.(*dns.A); ok {
					servers = append(servers, a.A.String())
					break
				}
			}
		} else {
			for _, extra := range r.Extra {
				if a, ok := extra.(*dns.AAAA); ok {
					servers = append(servers, a.AAAA.String())
					break
				}
			}
		}

		if len(servers) == 0 {
			for _, ns := range r.Ns {
				if a, ok := ns.(*dns.NS); ok {
					servers = append(servers, a.Ns)
					break
				}
			}
		}
	}
	return
}

func main() {
	clearOpts()
	if err := driver(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
