package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// HTTP makes a DNS query over HTTP(s)
type HTTP struct {
	Common
	TLSConfig    *tls.Config
	UserAgent    string
	Method       string
	HTTP2, HTTP3 bool
	NoPMTUd      bool

	conn *http.Client
}

func (h *HTTP) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if h.conn == nil || !h.ReuseConn {
		transport := http.DefaultTransport.(*http.Transport)
		transport.TLSClientConfig = h.TLSConfig
		h.conn = &http.Client{
			Transport: transport,
		}
		if h.HTTP2 {
			log.Debug("Using HTTP/2")
			h.conn.Transport = &http2.Transport{
				TLSClientConfig: h.TLSConfig,
				AllowHTTP:       true,
			}
		}
		if h.HTTP3 {
			log.Debug("Using HTTP/3")
			h.conn.Transport = &http3.Transport{
				TLSClientConfig: h.TLSConfig,
				QUICConfig: &quic.Config{
					DisablePathMTUDiscovery: h.NoPMTUd,
				},
			}
		}
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	var queryURL string
	var req *http.Request
	switch h.Method {
	case http.MethodGet:
		queryURL = h.Server + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
		req, err = http.NewRequest(http.MethodGet, queryURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating http request to %s: %w", queryURL, err)
		}
	case http.MethodPost:
		queryURL = h.Server
		req, err = http.NewRequest(http.MethodPost, queryURL, bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("creating http request to %s: %w", queryURL, err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", h.Method)
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
