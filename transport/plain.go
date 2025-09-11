package transport

import (
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Plain makes a DNS query over TCP or UDP (with TCP fallback)
type Plain struct {
	Common
	PreferTCP bool
	UDPBuffer uint16
	Timeout   time.Duration
}

func (p *Plain) Exchange(m *dns.Msg) (*dns.Msg, error) {
	tcpClient := dns.Client{Net: "tcp", Timeout: p.Timeout}
	if p.PreferTCP {
		reply, _, tcpErr := tcpClient.Exchange(m, p.Server)
		return reply, tcpErr
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
