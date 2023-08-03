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
}

func (t *TLS) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	conn, err := tls.DialWithDialer(
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
	defer conn.Close()

	if err = conn.Handshake(); err != nil {
		return nil, err
	}

	c := dns.Conn{Conn: conn}
	if err := c.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("write msg to %s: %v", t.Server, err)
	}

	return c.ReadMsg()
}
