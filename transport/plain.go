package transport

import (
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
