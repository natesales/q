package main

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestBuildURL(t *testing.T) {
	// Test with no query params
	u := buildURL("https://www.example.com", "")
	assert.Equal(t, "https://www.example.com", u.String())

	// Test with query params
	u = buildURL("https://www.example.com", "?foo=bar&baz=qux")
	assert.Equal(t, "https://www.example.com/%3Ffoo=bar&baz=qux", u.String())

	// Test with HTTP
	//goland:noinspection HttpUrlsUsage
	u = buildURL("http://www.example.com", "")
	assert.Equal(t, "http://www.example.com", u.String())
}

func TestODOHQuery(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	reply, err := odohQuery(msg, "odoh.cloudflare-dns.com", "odoh1.surfdomeinen.nl")
	assert.Nil(t, err)
	assert.Greater(t, len(reply.Answer), 0)
}

func TestODOHInvalidTarget(t *testing.T) {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}

	_, err := odohQuery(msg, "example.com", "odoh1.surfdomeinen.nl")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid serialized ObliviousDoHConfig")
}
