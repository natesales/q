package transport

import (
	"crypto/tls"
	"testing"

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

	reply, err := HTTP(&msg, &tls.Config{}, "https://cloudflare-dns.com/dns-query", "")
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}
