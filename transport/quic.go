package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
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

// QUIC makes a DNS query over QUIC
type QUIC struct {
	Server          string
	TLSConfig       *tls.Config
	NoPMTUD         bool
	AddLengthPrefix bool
	ReuseConn       bool

	conn *quic.Connection
}

func (q *QUIC) connection() quic.Connection {
	return *q.conn
}

// setServerName sets the TLS config server name to the QUIC server
func (q *QUIC) setServerName() {
	host, _, err := net.SplitHostPort(q.Server)
	if err != nil {
		log.Fatalf("invalid QUIC server address: %s", err)
	}
	q.TLSConfig.ServerName = host
}

func (q *QUIC) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if q.conn == nil || !q.ReuseConn {
		q.setServerName()
		if len(q.TLSConfig.NextProtos) == 0 {
			log.Debug("No ALPN tokens specified, using default: \"doq\"")
			q.TLSConfig.NextProtos = []string{"doq"}
		}
		log.Debugf("Dialing with QUIC ALPN tokens: %v", q.TLSConfig.NextProtos)
		conn, err := quic.DialAddr(
			context.Background(),
			q.Server,
			q.TLSConfig,
			&quic.Config{
				DisablePathMTUDiscovery: q.NoPMTUD,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("opening quic session to %s: %v", q.Server, err)
		}
		q.conn = &conn
	}

	// Clients and servers MUST NOT send the edns-tcp-keepalive EDNS(0) Option [RFC7828] in any messages sent
	// on a DoQ connection (because it is specific to the use of TCP/TLS as a transport).
	// https://datatracker.ietf.org/doc/html/rfc9250#section-5.5.2
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = q.connection().CloseWithError(DoQProtocolError, "") // Already closing the connection, so we don't care about the error
				q.conn = nil
				return nil, fmt.Errorf("EDNS0 TCP keepalive option is set")
			}
		}
	}

	stream, err := q.connection().OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open new stream to %s: %v", q.Server, err)
	}

	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to zero. The stream mapping for DoQ allows for unambiguous
	// correlation of queries and responses and so the Message ID field is
	// not required.
	// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	msg.Id = 0
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	if q.AddLengthPrefix {
		// All DNS messages (queries and responses) sent over DoQ connections
		// MUST be encoded as a 2-octet length field followed by the message
		// content as specified in [RFC1035].
		// https://datatracker.ietf.org/doc/html/rfc9250#section-4.2-4
		_, err = stream.Write(addPrefix(buf))
	} else {
		_, err = stream.Write(buf)
	}
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
		return nil, fmt.Errorf("reading response from %s: %s", q.Server, err)
	}
	if len(respBuf) == 0 {
		return nil, fmt.Errorf("empty response from %s", q.Server)
	}

	reply := dns.Msg{}
	if q.AddLengthPrefix {
		err = reply.Unpack(respBuf[2:])
	} else {
		err = reply.Unpack(respBuf)
	}
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %s", q.Server, err)
	}

	return &reply, nil
}

// addPrefix adds a 2-byte prefix with the DNS message length.
func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

func (q *QUIC) Close() error {
	return q.connection().CloseWithError(DoQNoError, "")
}
