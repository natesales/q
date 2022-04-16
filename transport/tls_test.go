package transport

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransportTLS(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := TLS(&msg, "dns.quad9.net:853", &tls.Config{}, 2*time.Second)
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}
