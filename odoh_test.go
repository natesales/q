package main

import (
	"github.com/miekg/dns"
	"testing"
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
	if err != nil {
		t.Error(err)
	}

	if len(reply.Answer) < 1 {
		t.Errorf("expected more than one answer, got %d", len(reply.Answer))
	}
}
