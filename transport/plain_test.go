package transport

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransportPlain(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := Plain(&msg, "9.9.9.9:53", false, 5*time.Second, dns.DefaultMsgSize)
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}
