package main

import (
	"github.com/miekg/dns"
	"strings"
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
