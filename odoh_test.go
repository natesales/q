package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestODOHQuery(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := odohQuery(msg, "odoh1.surfdomeinen.nl", "odoh.cloudflare-dns.com")
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestODOHInvalidUpstream(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	_, err := odohQuery(msg, "odoh1.surfdomeinen.nl", "example.com")
	if !(err != nil && strings.Contains(err.Error(), "Invalid serialized ObliviousDoHConfig")) {
		t.Errorf("expected odoh error, got %+v", err)
	}
}
