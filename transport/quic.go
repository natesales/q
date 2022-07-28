package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// DoQ Error Codes
// https://datatracker.ietf.org/doc/html/rfc9250#section-8.4
const (
	DoQNoError          = 0x0        // No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
	DoQInternalError    = 0x1        // The DoQ implementation encountered an internal error and is incapable of pursuing the transaction or the connection.
	DoQProtocolError    = 0x2        // The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
	DoQRequestCancelled = 0x3        // A DoQ client uses this to signal that it wants to cancel an outstanding transaction.
	DoQExcessiveLoad    = 0x4        // A DoQ implementation uses this to signal when closing a connection due to excessive load.
	DoQUnspecifiedError = 0x5        // A DoQ implementation uses this in the absence of a more specific error code.
	DoQErrorReserved    = 0xd098ea5e // Alternative error code used for tests.
)

var (
	DoQALPNTokens = []string{"doq"}
)

// QUIC makes a DNS query over QUIC
func QUIC(msg *dns.Msg,
	server string,
	tlsConfig *tls.Config,
	dialTimeout, handshakeTimeout, openStreamTimeout time.Duration,
	noPMTUD, keepAlive bool,
) (*dns.Msg, error) {
	log.Debugf("Dialing with QUIC ALPN tokens: %v", tlsConfig.NextProtos)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dialCancel()
	session, err := quic.DialAddrContext(dialCtx, server, tlsConfig, &quic.Config{
		HandshakeIdleTimeout:    handshakeTimeout,
		DisablePathMTUDiscovery: noPMTUD,
		KeepAlive:               keepAlive,
	})
	if err != nil {
		return nil, fmt.Errorf("opening quic session to %s: %v", server, err)
	}

	// Clients and servers MUST NOT send the edns-tcp-keepalive EDNS(0) Option [RFC7828] in any messages sent
	// on a DoQ connection (because it is specific to the use of TCP/TLS as a transport).
	// https://datatracker.ietf.org/doc/html/rfc9250#section-5.5.2
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(DoQProtocolError, "") // Already closing the connection, so we don't care about the error
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

	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to zero.  The stream mapping for DoQ allows for unambiguous
	// correlation of queries and responses and so the Message ID field is
	// not required.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
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
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2
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
