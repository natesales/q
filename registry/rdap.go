package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/openrdap/rdap"
	"gopkg.in/yaml.v3"
)

// queryRDAP performs an RDAP lookup using github.com/openrdap/rdap.
// When opts.RDAPServer or a non-IANA RIR is set, the server URL is supplied
// directly on the request, bypassing bootstrap.
func queryRDAP(ctx context.Context, opts Options) (string, error) {
	kind := Classify(opts.Target)

	req, err := buildRDAPRequest(kind, opts.Target)
	if err != nil {
		return "", err
	}

	base := opts.RDAPServer
	if base == "" {
		base = rirRDAPBase(opts.RIR)
	}
	if base != "" {
		serverURL, err := url.Parse(base)
		if err != nil {
			return "", fmt.Errorf("registry: parse rdap server %q: %w", base, err)
		}
		req = req.WithServer(serverURL)
	}
	req = req.WithContext(ctx)
	req.Timeout = opts.Timeout

	client := &rdap.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry: rdap: %w", err)
	}
	if resp == nil || resp.Object == nil {
		return "", fmt.Errorf("registry: rdap: empty response")
	}

	return formatRDAP(resp, opts.Format)
}

func buildRDAPRequest(kind Kind, target string) (*rdap.Request, error) {
	switch kind {
	case KindDomain:
		return &rdap.Request{Type: rdap.DomainRequest, Query: target}, nil
	case KindIPv4, KindIPv6:
		return &rdap.Request{Type: rdap.IPRequest, Query: target}, nil
	case KindASN:
		num := strings.TrimPrefix(strings.ToUpper(target), "AS")
		return &rdap.Request{Type: rdap.AutnumRequest, Query: num}, nil
	case KindNICHandle:
		return &rdap.Request{Type: rdap.EntityRequest, Query: target}, nil
	}
	return nil, fmt.Errorf("registry: cannot classify rdap target %q", target)
}

func formatRDAP(resp *rdap.Response, format string) (string, error) {
	switch normalizeFormat(format) {
	case "json", "raw":
		return marshalRDAPJSON(resp)
	case "yaml":
		return marshalRDAPYAML(resp)
	}

	if pretty := formatRDAPPretty(resp); pretty != "" {
		return pretty, nil
	}
	return marshalRDAPJSON(resp)
}

func marshalRDAPJSON(resp *rdap.Response) (string, error) {
	b, err := json.MarshalIndent(resp.Object, "", "  ")
	if err != nil {
		return "", fmt.Errorf("registry: marshal rdap: %w", err)
	}
	return string(b), nil
}

// marshalRDAPYAML re-encodes the server document. openrdap's structs have
// no yaml tags, so marshaling them emits lowercased Go names, nested
// Common/DecodeData fields, and every empty value. The last HTTP body is
// the object the client accepted (earlier entries are failed attempts).
//
// Numbers are decoded with UseNumber and integers that fit in int64 are
// emitted as integers. yaml.v3 formats float64 with 'g', which can turn a
// value into exponent form; keeping the server's decimal text avoids that.
func marshalRDAPYAML(resp *rdap.Response) (string, error) {
	body, err := rdapWireBody(resp)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("registry: decode rdap: %w", err)
	}
	b, err := yaml.Marshal(jsonValueToYAML(v))
	if err != nil {
		return "", fmt.Errorf("registry: marshal rdap: %w", err)
	}
	return string(b), nil
}

func rdapWireBody(resp *rdap.Response) ([]byte, error) {
	if resp == nil || len(resp.HTTP) == 0 {
		return nil, fmt.Errorf("registry: rdap: empty response body")
	}
	body := resp.HTTP[len(resp.HTTP)-1].Body
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("registry: rdap: empty response body")
	}
	return body, nil
}

// jsonValueToYAML walks a UseNumber decode result and replaces json.Number
// so yaml.v3 does not quote it or print it as a float64.
func jsonValueToYAML(v any) any {
	switch n := v.(type) {
	case map[string]any:
		for k, val := range n {
			n[k] = jsonValueToYAML(val)
		}
		return n
	case []any:
		for i, val := range n {
			n[i] = jsonValueToYAML(val)
		}
		return n
	case json.Number:
		return yamlNumber(n)
	default:
		return v
	}
}

func yamlNumber(n json.Number) any {
	if i, err := n.Int64(); err == nil {
		return i
	}
	// Wider than int64, or not an integer. Emit the server's exact text
	// instead of rounding through float64.
	s := n.String()
	tag := "!!float"
	if !strings.ContainsAny(s, ".eE") {
		tag = "!!int"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: s}
}
