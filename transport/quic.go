package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// DoQ Error Codes
// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-11#section-5.3
const (
	noError          = 0x0        // No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
	internalError    = 0x1        // The DoQ implementation encountered an internal error and is incapable of pursuing the transaction or the connection.
	protocolError    = 0x2        // The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
	requestCancelled = 0x3        // A DoQ client uses this to signal that it wants to cancel an outstanding transaction.
	excessiveLoad    = 0x4        // A DoQ implementation uses this to signal when closing a connection due to excessive load.
	unspecifiedError = 0x5        // A DoQ implementation uses this in the absence of a more specific error code.
	errorReserved    = 0xd098ea5e // Alternative error code used for tests.
)

// QUIC makes a DNS query over QUIC
func QUIC(msg *dns.Msg, server string, tlsConfig *tls.Config, dialTimeout, handshakeTimeout, openStreamTimeout time.Duration) (*dns.Msg, error) {
	dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dialCancel()
	session, err := quic.DialAddrContext(dialCtx, server, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("opening quic session to %s: %v", server, err)
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(protocolError, "") // Already closing the connection, so we don't care about the error
				return nil, fmt.Errorf("EDNS0 TCP keepalive option is set")
			}
		}
	}

	openStreamCtx, openStreamCancel := context.WithTimeout(context.Background(), openStreamTimeout)
	defer openStreamCancel()
	stream, err := session.OpenStreamSync(openStreamCtx)
	if err != nil {
		return nil, fmt.Errorf("open new stream to %s: %v", server, err)
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	msg.Id = 0
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	_, err = stream.Write(buf)
	if err != nil {
		return nil, err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	respBuf, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %s", server, err)
	}
	if len(respBuf) == 0 {
		return nil, fmt.Errorf("empty response from %s", server)
	}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf)
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %s", server, err)
	}

	return &reply, nil
}
