package transport

import (
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Plain makes a DNS query over TCP or UDP (with TCP fallback)
func Plain(m *dns.Msg, server string, preferTCP bool, timeout time.Duration, udpBuffer uint16) (*dns.Msg, error) {
	tcpClient := dns.Client{Net: "tcp", Timeout: timeout}
	if preferTCP {
		reply, _, tcpErr := tcpClient.Exchange(m, server)
		return reply, tcpErr
	}

	client := dns.Client{Timeout: timeout, UDPSize: udpBuffer}
	reply, _, err := client.Exchange(m, server)

	if reply != nil && reply.Truncated {
		log.Debugf("Truncated reply from %s for %s over UDP, retrying over TCP", server, m.Question[0].String())
		reply, _, err = tcpClient.Exchange(m, server)
	}

	return reply, err
}
