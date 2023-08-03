package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func odohTransport() *ODoH {
	return &ODoH{
		Target: "odoh.cloudflare-dns.com",
		Proxy:  "odoh.crypto.sx",
	}
}

func TestODoHBuildURL(t *testing.T) {
	// Test with no query params
	u := buildURL("https://www.example.com", "")
	assert.Equal(t, "https://www.example.com", u.String())

	// Test with query params
	u = buildURL("https://www.example.com", "?foo=bar&baz=qux")
	assert.Equal(t, "https://www.example.com/%3Ffoo=bar&baz=qux", u.String())

	// Test with HTTP
	//goland:noinspection HttpUrlsUsage
	u = buildURL("http://www.example.com", "")
	//goland:noinspection HttpUrlsUsage
	assert.Equal(t, "http://www.example.com", u.String())
}

func TestTransportODoHInvalidTarget(t *testing.T) {
	tp := odohTransport()
	tp.Target = "example.com"
	_, err := tp.Exchange(validQuery())
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid serialized ObliviousDoHConfig")
}

func TestTransportODoHInvalidProxy(t *testing.T) {
	tp := odohTransport()
	tp.Proxy = "example.com"
	_, err := tp.Exchange(validQuery())
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "responded with an invalid Content-Type header")
}
