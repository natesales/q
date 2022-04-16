package transport

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransportPlainUDP(t *testing.T) {
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

func TestTransportPlainPreferTCP(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := Plain(&msg, "9.9.9.9:53", true, 5*time.Second, dns.DefaultMsgSize)
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestTransportPlainInvalidResolver(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	_, err := Plain(&msg, "127.127.127.127:53", false, 1*time.Second, dns.DefaultMsgSize)
	assert.NotNil(t, err)
}

func TestTransportPlainLargeResponse(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   ".",
		Qtype:  dns.StringToType["AXFR"],
		Qclass: dns.ClassINET,
	}}
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Class:  dns.DefaultMsgSize,
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetDo()
	msg.Extra = append(msg.Extra, opt)

	_, err := Plain(&msg, "f.root-servers.net:53", false, 1*time.Second, dns.DefaultMsgSize)
	assert.Nil(t, err)
}
