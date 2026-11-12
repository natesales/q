package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type Transport interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
	Close() error
}

type Common struct {
	Server    string
	ReuseConn bool
	UseIPv4   bool
	UseIPv6   bool
}

func (c *Common) network(base string) string {
	if c.UseIPv4 {
		return base + "4"
	}
	if c.UseIPv6 {
		return base + "6"
	}
	return base
}

func (c *Common) resolveHost(ctx context.Context, host string) (string, error) {
	if !c.UseIPv4 && !c.UseIPv6 {
		return host, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		isV4 := ip.To4() != nil
		if (c.UseIPv4 && isV4) || (c.UseIPv6 && !isV4) {
			return host, nil
		}
		family := "IPv4"
		if c.UseIPv6 {
			family = "IPv6"
		}
		return "", fmt.Errorf("no %s address found for %s", family, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", host, err)
	}
	for _, a := range addrs {
		isV4 := a.IP.To4() != nil
		if c.UseIPv4 && isV4 {
			return a.IP.String(), nil
		}
		if c.UseIPv6 && !isV4 {
			return a.IP.String(), nil
		}
	}
	family := "IPv4"
	if c.UseIPv6 {
		family = "IPv6"
	}
	return "", fmt.Errorf("no %s address found for %s", family, host)
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
