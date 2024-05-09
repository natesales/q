package transport

import (
	"github.com/miekg/dns"
)

type Transport interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
	Close() error
}

type Common struct {
	Server    string
	ReuseConn bool
}

type Type string

const (
	TypePlain    Type = "plain"
	TypeTCP      Type = "tcp"
	TypeTLS      Type = "tls"
	TypeHTTP     Type = "http"
	TypeQUIC     Type = "quic"
	TypeDNSCrypt Type = "dnscrypt"
)

// Types is a list of all supported transports
var Types = []Type{TypePlain, TypeTCP, TypeTLS, TypeHTTP, TypeQUIC, TypeDNSCrypt}

// Interface guards
var (
	_ Transport = (*Plain)(nil)
	_ Transport = (*TLS)(nil)
	_ Transport = (*HTTP)(nil)
	_ Transport = (*ODoH)(nil)
	_ Transport = (*QUIC)(nil)
	_ Transport = (*DNSCrypt)(nil)
)
