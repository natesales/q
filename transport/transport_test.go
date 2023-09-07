package transport

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// validQuery creates a simple, valid query for testing
func validQuery() *dns.Msg {
	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.Id = dns.Id()
	msg.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.StringToType["A"],
		Qclass: dns.ClassINET,
	}}
	return &msg
}

// invalidQuery creates a simple, invalid query for testing
func invalidQuery() *dns.Msg {
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	msg.Id = dns.Id()
	msg.Question = []dns.Question{{
		Name: "invalid label!",
	}}
	return msg
}

func transportHarness(t *testing.T, transport Transport) {
	defer transport.Close()
	for _, tc := range []struct {
		// Name is the name of the test
		Name string

		// ShouldError is true if the test should error
		ShouldError bool

		// Query is the message to send
		Query *dns.Msg
	}{
		{Name: "ValidQuery", ShouldError: false, Query: validQuery()},
		{Name: "InvalidQuery", ShouldError: true, Query: invalidQuery()},
	} {
		t.Run("TransportHarness"+tc.Name, func(t *testing.T) {
			reply, err := transport.Exchange(tc.Query)
			if tc.ShouldError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tc.Query.Id, reply.Id)
				for _, q := range tc.Query.Question {
					for _, a := range reply.Answer {
						if q.Name == a.Header().Name {
							assert.Equal(t, q.Qtype, a.Header().Rrtype)
							assert.Equal(t, q.Qclass, a.Header().Class)
						}
					}
				}
			}
		})
	}
}

func TestTransportPlain(t *testing.T) {
	transportHarness(t, plainTransport())
}

func TestTransportTLS(t *testing.T) {
	transportHarness(t, tlsTransport())
}

func TestTransportQUIC(t *testing.T) {
	transportHarness(t, quicTransport())
}

func TestTransportHTTP(t *testing.T) {
	transportHarness(t, httpTransport())
}

func TestTransportReuseTLS(t *testing.T) {
	transport := tlsTransport()
	transport.ReuseConn = true
	transportHarness(t, transport)
}

func TestTransportReuseQUIC(t *testing.T) {
	transport := quicTransport()
	transport.ReuseConn = true
	transportHarness(t, transport)
}

func TestTransportReuseHTTP(t *testing.T) {
	transport := httpTransport()
	transport.ReuseConn = true
	transportHarness(t, transport)
}

// TODO: Enable test
//func TestTransportODoH(t *testing.T) {
//	transportHarness(t, odohTransport())
//}
//func TestTransportReuseODoH(t *testing.T) {
//	transport := odohTransport()
//	transport.ReuseConn = true
//	reuseTransportHarness(t, transport)
//}
