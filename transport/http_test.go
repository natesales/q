package transport

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransportHTTP(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := HTTP(&msg, &tls.Config{}, "https://cloudflare-dns.com/dns-query", "", "GET")
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestTransportHTTPInvalidResolver(t *testing.T) {
	_, err := HTTP(&dns.Msg{}, &tls.Config{}, "https://example.com", "", "GET")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unpacking DNS response")
}

func TestTransportHTTPServerError(t *testing.T) {
	_, err := HTTP(&dns.Msg{}, &tls.Config{}, "https://httpstat.us/500", "", "GET")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "got status code 500")
}

func TestTransportHTTPIDMismatch(t *testing.T) {
	go func() {
		http.ListenAndServe(":8085", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			msg := dns.Msg{}
			msg.Id = 1
			buf, err := msg.Pack()
			if err != nil {
				t.Errorf("error packing DNS message: %s", err)
				return
			}
			w.Write(buf)
		}))
	}()
	time.Sleep(50 * time.Millisecond)
	_, err := HTTP(&dns.Msg{}, &tls.Config{}, "http://localhost:8085", "", "GET")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "id mismatch")
}
