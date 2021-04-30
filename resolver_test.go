package main

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestResolveUDP(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		t.Error(err)
	}

	answers, qTime, err := Resolve("example.com", false, "", u, []uint16{dns.StringToType["A"]})
	if err != nil {
		t.Error(err)
	}

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	if len(answers) < 1 {
		t.Errorf("expected more than 1 answer, got %d", len(answers))
	}

	if queryTime > 1000 {
		t.Errorf("query took longer than 1 second, %d ms", queryTime)
	}
}

func TestResolveODOH(t *testing.T) {
	u, err := upstream.AddressToUpstream("https://odoh.cloudflare-dns.com", upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		t.Error(err)
	}

	answers, qTime, err := Resolve("example.com", false, "odoh1.surfdomeinen.nl", u, []uint16{dns.StringToType["A"]})
	if err != nil {
		t.Error(err)
	}

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	if len(answers) < 1 {
		t.Errorf("expected more than 1 answer, got %d", len(answers))
	}

	if queryTime > 5000 {
		t.Errorf("query took longer than 5 seconds, %d ms", queryTime)
	}
}
