package transport

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	log "github.com/sirupsen/logrus"
)

// HTTP makes a DNS query over HTTP(s)
type HTTP struct {
	Server    string
	TLSConfig *tls.Config
	UserAgent string
	Method    string
	Timeout   time.Duration
	HTTP3     bool
	NoPMTUd   bool
	ReuseConn bool

	conn *http.Client
}

func (h *HTTP) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if h.conn == nil || !h.ReuseConn {
		h.conn = &http.Client{
			Timeout: h.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: h.TLSConfig,
				MaxConnsPerHost: 1,
				MaxIdleConns:    1,
				Proxy:           http.ProxyFromEnvironment,
			},
		}
		if h.HTTP3 {
			log.Debug("Using HTTP/3")
			h.conn.Transport = &http3.RoundTripper{
				TLSClientConfig: h.TLSConfig,
				QuicConfig: &quic.Config{
					DisablePathMTUDiscovery: h.NoPMTUd,
				},
			}
		}
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	queryURL := h.Server + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest(h.Method, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", queryURL, err)
	}

	req.Header.Set("Accept", "application/dns-message")
	if h.UserAgent != "" {
		log.Debugf("Setting User-Agent to %s", h.UserAgent)
		req.Header.Set("User-Agent", h.UserAgent)
	}

	log.Debugf("[http] sending %s request to %s", h.Method, queryURL)
	resp, err := h.conn.Do(req)
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
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DNS response from %s: %w", queryURL, err)
	}

	return &response, nil
}

func (h *HTTP) Close() error {
	h.conn.CloseIdleConnections()
	return nil
}
