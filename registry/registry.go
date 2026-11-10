package registry

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// Kind classifies a registry-lookup target.
type Kind int

const (
	KindUnknown Kind = iota
	KindIPv4
	KindIPv6
	KindASN
	KindDomain
	KindNICHandle
)

func (k Kind) String() string {
	switch k {
	case KindIPv4:
		return "ipv4"
	case KindIPv6:
		return "ipv6"
	case KindASN:
		return "asn"
	case KindDomain:
		return "domain"
	case KindNICHandle:
		return "nic-handle"
	}
	return "unknown"
}

var (
	asnRe    = regexp.MustCompile(`^(?i)AS\d+$`)
	handleRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

// Classify inspects target and returns its Kind
func Classify(target string) Kind {
	t := strings.TrimSpace(target)
	if t == "" {
		return KindUnknown
	}
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() != nil {
			return KindIPv4
		}
		return KindIPv6
	}
	if asnRe.MatchString(t) {
		return KindASN
	}
	if strings.Contains(t, ".") {
		return KindDomain
	}
	if handleRe.MatchString(t) {
		return KindNICHandle
	}
	return KindUnknown
}

// Options controls a registry lookup.
type Options struct {
	Target      string
	UseRDAP     bool
	UseWHOIS    bool
	RDAPServer  string
	WhoisServer string
	RIR         string
	Format      string
	Timeout     time.Duration
}

// when passed --registry, attempts rdap first, then whois if fials
func Query(ctx context.Context, opts Options) (string, error) {
	if strings.TrimSpace(opts.Target) == "" {
		return "", fmt.Errorf("registry: empty target")
	}
	if !opts.UseRDAP && !opts.UseWHOIS {
		return "", fmt.Errorf("registry: neither RDAP nor WHOIS requested")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	// Lowercased here so the "iana" checks below and the RIR table lookup
	// share one spelling. Callers of lookupRIR pass that value through.
	opts.RIR = strings.ToLower(strings.TrimSpace(opts.RIR))
	if opts.RIR == "" {
		opts.RIR = "iana"
	}

	if Classify(opts.Target) == KindNICHandle &&
		opts.RIR == "iana" &&
		opts.RDAPServer == "" &&
		opts.WhoisServer == "" {
		if detected := DetectRIRFromHandle(opts.Target); detected != "" {
			log.Debugf("registry: detected RIR %s from handle %q", detected, opts.Target)
			opts.RIR = detected
		}
	}

	if opts.UseRDAP {
		out, err := queryRDAP(ctx, opts)
		if err == nil {
			return out, nil
		}
		if opts.UseWHOIS {
			log.Debugf("registry: RDAP failed (%s), falling back to WHOIS", err)
			return queryWHOIS(ctx, opts)
		}
		return "", err
	}
	return queryWHOIS(ctx, opts)
}

// matching whois(1) behavior to autoguess RIR based off of prefix
func DetectRIRFromHandle(handle string) string {
	h := strings.ToUpper(strings.TrimSpace(handle))
	switch {
	case strings.HasSuffix(h, "-RIPE"):
		return "ripe"
	case strings.HasSuffix(h, "-ARIN"), strings.HasPrefix(h, "ARIN-"):
		return "arin"
	case strings.HasSuffix(h, "-AP"):
		return "apnic"
	case strings.HasSuffix(h, "-LACNIC"):
		return "lacnic"
	case strings.HasSuffix(h, "-AFRINIC"):
		return "afrinic"
	}
	return ""
}

// rirService is one row of the RIR routing table. RDAP and WHOIS share these
// keys so a new registry cannot be added to only one protocol.
type rirService struct {
	rdapBase  string
	whoisHost string
}

var rirServices = map[string]rirService{
	"arin":    {rdapBase: "https://rdap.arin.net/registry", whoisHost: "whois.arin.net"},
	"ripe":    {rdapBase: "https://rdap.db.ripe.net", whoisHost: "whois.ripe.net"},
	"apnic":   {rdapBase: "https://rdap.apnic.net", whoisHost: "whois.apnic.net"},
	"lacnic":  {rdapBase: "https://rdap.lacnic.net/rdap", whoisHost: "whois.lacnic.net"},
	"afrinic": {rdapBase: "https://rdap.afrinic.net/rdap", whoisHost: "whois.afrinic.net"},
}

// lookupRIR returns the service row for rir. rir must already be
// lowercase; Query trims and lowercases opts.RIR before calling it.
func lookupRIR(rir string) (rirService, bool) {
	svc, ok := rirServices[rir]
	return svc, ok
}

// normalizeFormat lowercases an output format and treats "yml" as "yaml".
func normalizeFormat(format string) string {
	switch f := strings.ToLower(strings.TrimSpace(format)); f {
	case "yml":
		return "yaml"
	default:
		return f
	}
}

// rirRDAPBase returns the RDAP base URL for a known RIR. Unknown values,
// including "iana", return "" so the RDAP client uses IANA bootstrap.
func rirRDAPBase(rir string) string {
	if svc, ok := lookupRIR(rir); ok {
		return svc.rdapBase
	}
	return ""
}

// rirWhoisHost returns the port-43 host for a known RIR. Unknown values,
// including "iana", fall back to whois.iana.org.
func rirWhoisHost(rir string) string {
	if svc, ok := lookupRIR(rir); ok {
		return svc.whoisHost
	}
	return "whois.iana.org"
}
