package cli

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type Flags struct {
	Name             string        `short:"q" long:"qname" description:"Query name"`
	Server           []string      `short:"s" long:"server" description:"DNS server(s)"`
	Types            []string      `short:"t" long:"type" description:"RR type (e.g. A, AAAA, MX, etc.) or type integer"`
	Reverse          bool          `short:"x" long:"reverse" description:"Reverse lookup"`
	DNSSEC           bool          `short:"d" long:"dnssec" description:"Set the DO (DNSSEC OK) bit in the OPT record"`
	NSID             bool          `short:"n" long:"nsid" description:"Set EDNS0 NSID opt"`
	ClientSubnet     string        `long:"subnet" description:"Set EDNS0 client subnet"`
	Chaos            bool          `short:"c" long:"chaos" description:"Use CHAOS query class"`
	Class            uint16        `short:"C" description:"Set query class (default: IN 0x01)" default:"1"`
	ODoHProxy        string        `short:"p" long:"odoh-proxy" description:"ODoH proxy"`
	Timeout          time.Duration `long:"timeout" description:"Query timeout" default:"10s"`
	Pad              bool          `long:"pad" description:"Set EDNS0 padding"`
	HTTP3            bool          `long:"http3" description:"Use HTTP/3 for DoH"`
	IDCheck          bool          `long:"id-check" description:"Check DNS response ID (default: true)"`
	ReuseConn        bool          `long:"reuse-conn" description:"Reuse connections across queries to the same server (default: true)"`
	TXTConcat        bool          `long:"txtconcat" description:"Concatenate TXT responses"`
	ID               int           `long:"qid" description:"Set query ID (-1 for random)" default:"-1"`
	BootstrapServer  string        `short:"b" long:"bootstrap-server" description:"DNS server to use for bootstrapping"`
	BootstrapTimeout time.Duration `long:"bootstrap-timeout" description:"Bootstrapping timeout" default:"5s"`
	Cookie           string        `long:"cookie" description:"EDNS0 cookie"`

	// Special query modes
	RecAXFR bool `long:"recaxfr" description:"Perform recursive AXFR"`

	// Output
	Format         string `short:"f" long:"format" description:"Output format (pretty, column, json, yaml, raw)" default:"pretty"`
	PrettyTTLs     bool   `long:"pretty-ttls" description:"Format TTLs in human readable format (default: true)"`
	ShortTTLs      bool   `long:"short-ttls" description:"Remove zero components of pretty TTLs. (24h0m0s->24h) (default: true)"`
	Color          bool   `long:"color" description:"Enable color output"`
	ShowQuestion   bool   `long:"question" description:"Show question section"`
	ShowAnswer     bool   `long:"answer" description:"Show answer section (default: true)"`
	ShowAuthority  bool   `long:"authority" description:"Show authority section"`
	ShowAdditional bool   `long:"additional" description:"Show additional section"`
	ShowStats      bool   `short:"S" long:"stats" description:"Show time statistics"`
	ShowAll        bool   `long:"all" description:"Show all sections and statistics"`
	Whois          bool   `short:"w" description:"Resolve ASN/ASName for A and AAAA records"`
	ValueOnly      bool   `short:"r" long:"short" description:"Show record values only"`
	ResolveIPs     bool   `short:"R" long:"resolve-ips" description:"Resolve PTR records for IP addresses in A and AAAA records"`

	// Header flags
	AuthoritativeAnswer bool `long:"aa" description:"Set AA (Authoritative Answer) flag in query"`
	AuthenticData       bool `long:"ad" description:"Set AD (Authentic Data) flag in query"`
	CheckingDisabled    bool `long:"cd" description:"Set CD (Checking Disabled) flag in query"`
	RecursionDesired    bool `long:"rd" description:"Set RD (Recursion Desired) flag in query (default: true)"`
	RecursionAvailable  bool `long:"ra" description:"Set RA (Recursion Available) flag in query"`
	Zero                bool `long:"z" description:"Set Z (Zero) flag in query"`
	Truncated           bool `long:"t" description:"Set TC (Truncated) flag in query"`

	// TLS parameters
	TLSInsecureSkipVerify bool     `short:"i" long:"tls-insecure-skip-verify" description:"Disable TLS certificate verification"`
	TLSServerName         string   `long:"tls-server-name" description:"TLS server name for host verification"`
	TLSMinVersion         string   `long:"tls-min-version" description:"Minimum TLS version to use" default:"1.0"`
	TLSMaxVersion         string   `long:"tls-max-version" description:"Maximum TLS version to use" default:"1.3"`
	TLSNextProtos         []string `long:"tls-next-protos" description:"TLS next protocols for ALPN"`
	TLSCipherSuites       []string `long:"tls-cipher-suites" description:"TLS cipher suites"`
	TLSCurvePreferences   []string `long:"tls-curve-preferences" description:"TLS curve preferences"`
	TLSClientCertificate  string   `long:"tls-client-cert" description:"TLS client certificate file"`
	TLSClientKey          string   `long:"tls-client-key" description:"TLS client key file"`
	TLSKeyLogFile         string   `long:"tls-key-log-file" env:"SSLKEYLOGFILE" description:"TLS key log file"`

	// HTTP
	HTTPUserAgent string `long:"http-user-agent" description:"HTTP user agent" default:""`
	HTTPMethod    string `long:"http-method" description:"HTTP method" default:"GET"`

	PMTUD bool `long:"pmtud" description:"PMTU discovery (default: true)"`

	// QUIC
	QUICALPNTokens   []string `long:"quic-alpn-tokens" description:"QUIC ALPN tokens" default:"doq" default:"doq-i11"` //nolint:golint,staticcheck
	QUICLengthPrefix bool     `long:"quic-length-prefix" description:"Add RFC 9250 compliant length prefix (default: true)"`

	// DNSCrypt
	DNSCryptTCP       bool   `long:"dnscrypt-tcp" description:"Use TCP for DNSCrypt (default UDP)"`
	DNSCryptUDPSize   int    `long:"dnscrypt-udp-size" description:"Maximum size of a DNS response this client can sent or receive" default:"0"`
	DNSCryptPublicKey string `long:"dnscrypt-key" description:"DNSCrypt public key"`
	DNSCryptProvider  string `long:"dnscrypt-provider" description:"DNSCrypt provider name"`

	DefaultRRTypes []string `long:"default-rr-types" description:"Default record types" default:"A" default:"AAAA" default:"NS" default:"MX" default:"TXT" default:"CNAME"` //nolint:golint,staticcheck

	UDPBuffer   uint16 `long:"udp-buffer" description:"Set EDNS0 UDP size in query" default:"1232"`
	Verbose     bool   `short:"v" long:"verbose" description:"Show verbose log messages"`
	Trace       bool   `long:"trace" description:"Show trace log messages"`
	ShowVersion bool   `short:"V" long:"version" description:"Show version and exit"`
}

// ParsePlusFlags parses a list of flags notated by +[no]flag and sets the corresponding opts fields
func ParsePlusFlags(opts *Flags, args []string) {
	for _, arg := range args {
		if len(arg) > 3 && arg[0] == '+' {
			argFound := false

			flag := strings.ToLower(arg[3:])
			state := arg[1:3] != "no"
			if state {
				flag = strings.ToLower(arg[1:])
			}

			v := reflect.Indirect(reflect.ValueOf(opts))
			vT := v.Type()
			for i := 0; i < v.NumField(); i++ {
				fieldTag := vT.Field(i).Tag.Get("long")
				if vT.Field(i).Type == reflect.TypeOf(true) && fieldTag == flag {
					argFound = true
					reflect.ValueOf(opts).Elem().Field(i).SetBool(state)
					break
				}
			}

			if !argFound {
				log.Fatalf("unknown flag %s", arg)
			}
		}
	}
}

// SetDefaultTrueBools enables boolean flags that are true by default
func SetDefaultTrueBools(opts *Flags) {
	v := reflect.Indirect(reflect.ValueOf(opts))
	vT := v.Type()
	for i := 0; i < v.NumField(); i++ {
		defaultTrue := strings.Contains(vT.Field(i).Tag.Get("description"), "default: true")
		if vT.Field(i).Type == reflect.TypeOf(true) && defaultTrue {
			reflect.ValueOf(opts).Elem().Field(i).SetBool(true)
		}
	}
}

// SetFalseBooleans sets boolean flags to false from a given argument list and returns the remaining arguments
func SetFalseBooleans(opts *Flags, args []string) []string {
	// Add equal signs to separated flags (e.g. --foo bar becomes --foo=bar)
	for i, arg := range args {
		if arg[0] == '-' && !strings.Contains(arg, "=") && i+1 < len(args) && (args[i+1] == "true" || args[i+1] == "false") {
			args[i] = arg + "=" + args[i+1]
			args = append(args[:i+1], args[i+2:]...)
		}
	}

	var remainingArgs []string
	for _, arg := range args {

		if strings.HasSuffix(arg, "=true") || strings.HasSuffix(arg, "=false") {
			flag := strings.ToLower(strings.TrimLeft(arg, "-"))
			flag = strings.TrimSuffix(flag, "=true")
			flag = strings.TrimSuffix(flag, "=false")

			v := reflect.Indirect(reflect.ValueOf(opts))
			vT := v.Type()
			for i := 0; i < v.NumField(); i++ {
				if vT.Field(i).Type == reflect.TypeOf(true) && (vT.Field(i).Tag.Get("long") == flag || vT.Field(i).Tag.Get("short") == flag) {
					boolState := strings.HasSuffix(arg, "=true")
					log.Tracef("Setting %s to %t", arg, boolState)
					reflect.ValueOf(opts).Elem().Field(i).SetBool(boolState)
					break
				}
			}
		} else {
			remainingArgs = append(remainingArgs, arg)
		}
	}

	log.Tracef("remaining args: %v", remainingArgs)
	return remainingArgs
}

// ParseRRTypes parses a list of RR types in string format ("A", "AAAA", etc.) or integer format (1, 28, etc.)
func ParseRRTypes(t []string) (map[uint16]bool, error) {
	rrTypes := make(map[uint16]bool, len(t))
	for _, rrType := range t {
		typeCode, ok := dns.StringToType[strings.ToUpper(rrType)]
		if ok {
			rrTypes[typeCode] = true
		} else {
			typeCode, err := strconv.Atoi(rrType)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid RR type", rrType)
			}
			log.Debugf("using RR type %d as integer", typeCode)
			rrTypes[uint16(typeCode)] = true
		}
	}
	return rrTypes, nil
}
