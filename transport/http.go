package transport

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// HTTP makes a DNS query over HTTP(s)
func HTTP(m *dns.Msg, tlsConfig *tls.Config, server, userAgent, method string) (*dns.Msg, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			MaxConnsPerHost: 1,
			MaxIdleConns:    1,
		},
		Timeout: 5 * time.Second,
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	queryURL := server + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest(method, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", queryURL, err)
	}

	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", queryURL, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", queryURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got status code %d from %s", resp.StatusCode, queryURL)
	}

	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("unpacking DNS response from %s: %w", queryURL, err)
	}

	if response.Id != m.Id {
		err = dns.ErrId
	}

	return &response, err
}
