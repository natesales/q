package transport

import "github.com/miekg/dns"

type Transport interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
	Close() error
}

const (
	TypePlain    = "plain"
	TypeTCP      = "tcp"
	TypeTLS      = "tls"
	TypeHTTP     = "http"
	TypeQUIC     = "quic"
	TypeDNSCrypt = "dnscrypt"
)

// Interface guards
var (
	_ Transport = (*Plain)(nil)
	_ Transport = (*TLS)(nil)
	_ Transport = (*HTTP)(nil)
	_ Transport = (*ODoH)(nil)
	_ Transport = (*QUIC)(nil)
	_ Transport = (*DNSCrypt)(nil)
)
