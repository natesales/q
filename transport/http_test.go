package transport

import (
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func httpTransport() *HTTP {
	return &HTTP{
		Common: Common{
			Server: "https://cloudflare-dns.com/dns-query",
		},
		Method: http.MethodGet,
	}
}

func TestTransportHTTPPOST(t *testing.T) {
	tp := httpTransport()
	tp.Method = http.MethodPost
	reply, err := tp.Exchange(validQuery())
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestTransportHTTP3(t *testing.T) {
	tp := httpTransport()
	tp.HTTP3 = true
	reply, err := tp.Exchange(validQuery())
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestTransportHTTPInvalidResolver(t *testing.T) {
	tp := httpTransport()
	tp.Server = "https://example.com"
	_, err := tp.Exchange(validQuery())
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unpacking DNS response")
}

func TestTransportHTTPServerError(t *testing.T) {
	listen := ":5380"
	go func() {
		if err := http.ListenAndServe(listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Server Error", http.StatusInternalServerError)
		})); err != nil {
			t.Errorf("error starting HTTP server: %s", err)
		}
	}()
	time.Sleep(50 * time.Millisecond) // Wait for server to start

	tp := httpTransport()
	tp.Server = "http://localhost" + listen
	_, err := tp.Exchange(validQuery())
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "got status code 500")
}

func TestTransportHTTPIDMismatch(t *testing.T) {
	listen := ":5381"
	go func() {
		if err := http.ListenAndServe(listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			msg := dns.Msg{}
			msg.Id = 1
			buf, err := msg.Pack()
			if err != nil {
				t.Errorf("error packing DNS message: %s", err)
				return
			}
			if _, err := w.Write(buf); err != nil {
				t.Errorf("error writing DNS message: %s", err)
			}
		})); err != nil {
			t.Errorf("error starting HTTP server: %s", err)
		}
	}()
	time.Sleep(50 * time.Millisecond) // Wait for server to start

	tp := httpTransport()
	tp.Server = "http://localhost" + listen
	query := validQuery()
	reply, err := tp.Exchange(query)
	assert.Nil(t, err)
	assert.Equal(t, uint16(1), reply.Id)
	assert.NotEqual(t, 1, query.Id)
}
