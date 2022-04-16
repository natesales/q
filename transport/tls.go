package transport

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"time"
)

// TLS makes a DNS query over TLS
func TLS(msg *dns.Msg, server string, tlsConfig *tls.Config, tcpDialTimeout time.Duration) (*dns.Msg, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: tcpDialTimeout,
	}, "tcp", server, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err = conn.Handshake(); err != nil {
		return nil, err
	}

	c := dns.Conn{Conn: conn}
	if err := c.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("write msg to %s: %v", server, err)
	}

	reply, err := c.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("reading request from %s: %v", server, err)
	} else if reply.Id != msg.Id {
		err = dns.ErrId
	}

	return reply, err
}
