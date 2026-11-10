package registry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// whoisHopLimit caps the number of refer-chain hops to avoid infinite loops
const whoisHopLimit = 5

type whoisHop struct {
	Server string `json:"server" yaml:"server"`
	Body   string `json:"body" yaml:"body"`
}

// queryWHOIS performs a port-43 WHOIS lookup, following referral pointers up to
// whoisHopLimit times.
func queryWHOIS(ctx context.Context, opts Options) (string, error) {
	start := opts.WhoisServer
	if start == "" {
		start = rirWhoisHost(opts.RIR)
	}

	hops, err := whoisChain(ctx, opts.Target, start, opts.Timeout)
	if err != nil && len(hops) == 0 {
		return "", err
	}

	return formatWhois(hops, opts.Format)
}

func formatWhois(hops []whoisHop, format string) (string, error) {
	payload := struct {
		Hops []whoisHop `json:"hops" yaml:"hops"`
	}{Hops: hops}
	switch normalizeFormat(format) {
	case "json":
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", fmt.Errorf("registry: marshal whois: %w", err)
		}
		return string(b), nil
	case "yaml":
		// yaml.v3 quotes a string that contains CR, trailing whitespace, or
		// invalid UTF-8 (the last is emitted as !!binary). Rewrite a copy so
		// the body is a block scalar and invalid bytes match JSON's U+FFFD.
		// Text output keeps the original body; JSON still substitutes U+FFFD
		// inside encoding/json. The rewritten form is not byte-identical to
		// the port-43 reply.
		norm := make([]whoisHop, len(hops))
		for i, h := range hops {
			norm[i] = whoisHop{Server: h.Server, Body: normalizeWhoisBody(h.Body)}
		}
		payload.Hops = norm
		b, err := yaml.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("registry: marshal whois: %w", err)
		}
		return string(b), nil
	}

	var sb strings.Builder
	for i, h := range hops {
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, ";; Server: %s\n", h.Server)
		sb.WriteString(h.Body)
		if !strings.HasSuffix(h.Body, "\n") {
			sb.WriteString("\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// normalizeWhoisBody converts a port-43 body into text yaml.v3 can render as
// a block scalar: LF line endings, no trailing whitespace, valid UTF-8.
// Invalid UTF-8 byte runs become U+FFFD, matching the replacement JSON uses.
func normalizeWhoisBody(body string) string {
	body = strings.ToValidUTF8(body, "\uFFFD")
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRightFunc(line, unicode.IsSpace)
	}
	return strings.Join(lines, "\n")
}

func whoisChain(ctx context.Context, target, start string, timeout time.Duration) ([]whoisHop, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var hops []whoisHop
	server := start
	seen := map[string]bool{}

	for i := 0; i < whoisHopLimit; i++ {
		// Dial the validated spelling. The seen key is canonical, so a
		// trailing root dot or another writing of the same IP does not
		// query that endpoint again.
		host := withDefaultPort(server, "43")
		key := whoisEndpointKey(host)
		if key == "" || seen[key] {
			break
		}
		seen[key] = true

		body, err := whoisExchange(ctx, host, target, timeout)
		if err != nil {
			if len(hops) == 0 {
				return nil, fmt.Errorf("registry: whois %s: %w", host, err)
			}
			hops = append(hops, whoisHop{Server: host, Body: fmt.Sprintf(";; error: %v", err)})
			return hops, nil
		}
		hops = append(hops, whoisHop{Server: host, Body: body})

		next := parseWhoisReferral(body)
		if next == "" {
			return hops, nil
		}
		server = next
	}
	return hops, nil
}

// whoisEndpointKey folds equivalent endpoints into one loop-detection key.
// Hostnames are lowercased and lose one trailing root dot. IP addresses use
// net.IP.String, so 2001:db8::1 and [2001:db8::1]:43 match. The port stays
// in the key; a missing port is 43.
func whoisEndpointKey(hostport string) string {
	if hostport == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if ip := net.ParseIP(hostport); ip != nil {
			return net.JoinHostPort(ip.String(), "43")
		}
		host, port = hostport, "43"
	} else if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return net.JoinHostPort(host, port)
}

func whoisExchange(ctx context.Context, hostport, query string, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	if err != nil {
		return string(b), err
	}
	return string(b), nil
}

// parseWhoisReferral scans the body for a referral line and returns the host
// (with optional port) it points at, or "" if none. Recognized keys are
// refer, whois, Whois Server, Registrar WHOIS Server, and ReferralServer.
// The first value that normalizes to a dialable host wins; placeholders and
// non-WHOIS URLs are skipped.
func parseWhoisReferral(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if value == "" {
			continue
		}
		switch key {
		case "refer", "whois", "whois server", "registrar whois server", "referralserver":
			if host := normalizeWhoisReferral(value); host != "" {
				return host
			}
		}
	}
	return ""
}

// normalizeWhoisReferral reduces a referral value to host or host:port.
// whois:// and rwhois:// are stripped case-insensitively, without lowercasing
// the rest of the string (ToLower can change the byte length). Any other
// scheme is rejected. A path, if present, is dropped. The result is returned
// only when it is a dialable host[:port]; placeholders such as "NONE" are not.
func normalizeWhoisReferral(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		scheme := v[:i]
		if !strings.EqualFold(scheme, "whois") && !strings.EqualFold(scheme, "rwhois") {
			return ""
		}
		v = v[i+len("://"):]
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if !validWhoisEndpoint(v) {
		return ""
	}
	return v
}

func validWhoisEndpoint(s string) bool {
	if s == "" {
		return false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// SplitHostPort rejects a bare IPv6 address because it has no port.
		// whoisChain adds port 43, and JoinHostPort brackets the address.
		// Anything else with a colon (an empty port, an extra colon) is not
		// host[:port].
		if strings.Contains(s, ":") {
			return net.ParseIP(s) != nil
		}
		host = s
	} else if !validWhoisPort(port) {
		return false
	}
	return validWhoisHost(host)
}

func validWhoisPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

func validWhoisHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	// A port-43 target is an FQDN. A single label is not dialed, which drops
	// placeholders such as "NONE". One trailing root dot is an absolute name
	// and is removed only for the label check; the dialed value keeps it.
	if strings.HasPrefix(host, ".") || !strings.Contains(host, ".") {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if !validWhoisLabel(label) {
			return false
		}
	}
	return true
}

func validWhoisLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func withDefaultPort(hostport, port string) string {
	if hostport == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, port)
}
