package main

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"strings"
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

	answers, qTime, err := resolve("example.com", false, false, "", u, []uint16{dns.StringToType["A"]})
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

func TestDNSSECResolveUDP(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		t.Error(err)
	}

	answers, qTime, err := resolve("example.com", false, true, "", u, []uint16{dns.StringToType["A"]})
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

	answers, qTime, err := resolve("example.com", false, false, "odoh1.surfdomeinen.nl", u, []uint16{dns.StringToType["A"]})
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

func TestInvalidUDPResolver(t *testing.T) {
	u, err := upstream.AddressToUpstream("127.127.127.127:1", upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		t.Error(err)
	}

	_, _, err = resolve("example.com", false, false, "", u, []uint16{dns.StringToType["A"]})
	if !(err != nil && strings.Contains(err.Error(), "connection refused")) {
		t.Errorf("expected connect error, got %+v", err)
	}
}

func TestResolverChaosClass(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		t.Error(err)
	}

	answers, qTime, err := resolve("id.server", true, false, "", u, []uint16{dns.StringToType["TXT"]})
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
