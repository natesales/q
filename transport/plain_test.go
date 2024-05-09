package transport

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func plainTransport() *Plain {
	return &Plain{
		Common: Common{
			Server: "9.9.9.9:53",
		},
		PreferTCP: false,
		UDPBuffer: 1232,
	}
}

func TestTransportPlainPreferTCP(t *testing.T) {
	tp := plainTransport()
	tp.PreferTCP = true
	reply, err := tp.Exchange(validQuery())
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestTransportPlainInvalidResolver(t *testing.T) {
	tp := plainTransport()
	tp.Server = "127.127.127.127:53"
	_, err := tp.Exchange(validQuery())
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

	tp := plainTransport()
	tp.Server = "f.root-servers.net:53"
	reply, err := tp.Exchange(&msg)
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}
