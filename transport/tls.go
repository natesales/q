package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// TLS makes a DNS query over TLS
type TLS struct {
	Server    string
	TLSConfig *tls.Config
	Timeout   time.Duration
	ReuseConn bool

	conn *tls.Conn
}

func (t *TLS) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if t.conn == nil || !t.ReuseConn {
		var err error
		t.conn, err = tls.DialWithDialer(
			&net.Dialer{
				Timeout: t.Timeout,
			},
			"tcp",
			t.Server,
			t.TLSConfig,
		)
		if err != nil {
			return nil, err
		}
		if err = t.conn.Handshake(); err != nil {
			return nil, err
		}
	}

	c := dns.Conn{Conn: t.conn}
	if err := c.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("write msg to %s: %v", t.Server, err)
	}

	return c.ReadMsg()
}

// Close closes the TLS connection
func (t *TLS) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}
