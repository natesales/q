package transport

import (
	"fmt"
	"net"
	"time"

	"github.com/charmbracelet/log"
	"github.com/miekg/dns"
)

// Plain makes a DNS query over TCP or UDP (with TCP fallback)
type Plain struct {
	Common
	PreferTCP bool
	EDNS      bool
	UDPBuffer uint16
	Timeout   time.Duration
}

func (p *Plain) Exchange(m *dns.Msg) (*dns.Msg, error) {
	host, _, err := net.SplitHostPort(p.Server)
	if err == nil {
		ip := net.ParseIP(host)
		if ip != nil && ip.IsMulticast() {
			log.Debugf("Detected multicast server %s, using relaxed mDNS exchange logic", p.Server)

			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return nil, fmt.Errorf("mdns listen: %w", err)
			}
			defer conn.Close()

			if err := conn.SetDeadline(time.Now().Add(p.Timeout)); err != nil {
				return nil, fmt.Errorf("mdns set deadline: %w", err)
			}

			buf, err := m.Pack()
			if err != nil {
				return nil, fmt.Errorf("mdns pack: %w", err)
			}

			dstAddr, err := net.ResolveUDPAddr("udp", p.Server)
			if err != nil {
				return nil, fmt.Errorf("mdns resolve: %w", err)
			}
			if _, err := conn.WriteTo(buf, dstAddr); err != nil {
				return nil, fmt.Errorf("mdns write: %w", err)
			}

			recvBuf := make([]byte, p.UDPBuffer)
			n, _, err := conn.ReadFrom(recvBuf)
			if err != nil {
				return nil, fmt.Errorf("mdns read: %w", err)
			}

			reply := new(dns.Msg)
			if err := reply.Unpack(recvBuf[:n]); err != nil {
				return nil, fmt.Errorf("mdns unpack: %w", err)
			}

			return reply, nil
		}
	}

	tcpClient := dns.Client{Net: "tcp", Timeout: p.Timeout}
	if p.PreferTCP {
		reply, _, tcpErr := tcpClient.Exchange(m, p.Server)
		return reply, tcpErr
	}

	// Ensure an EDNS0 OPT record is present (if enabled) and advertises our UDP buffer size
	// so large UDP responses are either sized appropriately or marked truncated, allowing TCP retry.
	if p.EDNS {
		if opt := m.IsEdns0(); opt == nil {
			m.Extra = append(m.Extra, &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Class:  p.UDPBuffer, // UDP payload size
					Rrtype: dns.TypeOPT,
				},
			})
		} else if opt.UDPSize() < p.UDPBuffer {
			opt.SetUDPSize(p.UDPBuffer)
		}
	}

	client := dns.Client{UDPSize: p.UDPBuffer, Timeout: p.Timeout}
	reply, _, err := client.Exchange(m, p.Server)

	if reply != nil && reply.Truncated {
		log.Debugf("Truncated reply from %s for %s over UDP, retrying over TCP", p.Server, m.Question[0].String())
		reply, _, err = tcpClient.Exchange(m, p.Server)
	}

	return reply, err
}

// Close is a no-op for the plain transport
func (p *Plain) Close() error {
	return nil
}
