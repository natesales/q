package main

import (
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestResolverUDP(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", &upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	assert.Nil(t, err)

	answers, qTime, err := resolve("example.com", false, false, "", u, []uint16{dns.StringToType["A"]},
		false, false, false, true, 4096)
	assert.Nil(t, err)

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	assert.Greater(t, len(answers), 0)
	assert.Less(t, queryTime, uint16(1000))
}

func TestResolverDNSSEC(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", &upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	assert.Nil(t, err)

	answers, qTime, err := resolve("example.com", false, true, "", u, []uint16{dns.StringToType["A"]},
		false, false, false, true, 4096)
	assert.Nil(t, err)

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	assert.Greater(t, len(answers), 0)
	assert.Less(t, queryTime, uint16(1000))
}

func TestResolverODoH(t *testing.T) {
	u, err := upstream.AddressToUpstream("https://odoh.cloudflare-dns.com", &upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	assert.Nil(t, err)

	answers, qTime, err := resolve("example.com", false, false, "odoh1.surfdomeinen.nl", u, []uint16{dns.StringToType["A"]},
		false, false, false, true, 4096)
	assert.Nil(t, err)

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	assert.Greater(t, len(answers), 0)
	assert.Less(t, queryTime, uint16(1000))
}

func TestResolverInvalidUDPUpstream(t *testing.T) {
	u, err := upstream.AddressToUpstream("127.127.127.127:1", &upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	assert.Nil(t, err)

	_, _, err = resolve("example.com", false, false, "", u, []uint16{dns.StringToType["A"]},
		false, false, false, true, 4096)
	if !(err != nil && strings.Contains(err.Error(), "connection refused")) {
		t.Errorf("expected connect error, got %+v", err)
	}
}

func TestResolverChaosClass(t *testing.T) {
	u, err := upstream.AddressToUpstream("1.1.1.1:53", &upstream.Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: opts.Insecure,
	})
	assert.Nil(t, err)

	answers, qTime, err := resolve(
		"id.server", true, false, "", u, []uint16{dns.StringToType["TXT"]},
		false, false, false, true, 4096)
	assert.Nil(t, err)

	queryTime := uint16(qTime / time.Millisecond) // Convert to milliseconds

	assert.Greater(t, len(answers), 0)
	assert.Less(t, queryTime, uint16(1000))
}
