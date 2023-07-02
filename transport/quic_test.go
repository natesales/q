package transport

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransportQUIC(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := QUIC(&msg, "dns.adguard.com:8853", &tls.Config{NextProtos: DoQALPNTokens}, 2*time.Second, 2*time.Second, 2*time.Second, false, true)
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}
