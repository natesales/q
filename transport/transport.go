package transport

import "github.com/miekg/dns"

type Transport interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
	Close() error
}

// Interface guards
var (
	_ Transport = (*Plain)(nil)
	_ Transport = (*TLS)(nil)
	_ Transport = (*HTTP)(nil)
	_ Transport = (*ODoH)(nil)
	_ Transport = (*QUIC)(nil)
)
