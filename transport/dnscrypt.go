package transport

import (
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type DNSCrypt struct {
	Common
	ServerStamp string
	TCP         bool // default false (UDP)
	UDPSize     int

	// ServerStamp takes precedence if set
	PublicKey    string
	ProviderName string

	resolver *dnscrypt.ResolverInfo
	client   *dnscrypt.Client
}

func (d *DNSCrypt) setup() {
	if d.client == nil || d.resolver == nil || !d.ReuseConn {
		d.client = &dnscrypt.Client{
			Net:     "udp",
			Timeout: d.Timeout,
			UDPSize: d.UDPSize,
		}

		if d.ServerStamp == "" {
			stamp, err := dnsstamps.NewDNSCryptServerStampFromLegacy(d.Server, d.PublicKey, d.ProviderName, 0)
			if err != nil {
				log.Fatalf("failed to create stamp from provider information: %s", err)
			}
			d.ServerStamp = stamp.String()
			log.Debugf("Created DNS stamp from manual DNSCrypt configuration: %s", d.ServerStamp)
		}

		// Resolve server DNS stamp
		ro, err := d.client.Dial(d.ServerStamp)
		if err != nil {
			log.Fatalf("failed to dial DNSCrypt server: %s", err)
		}
		d.resolver = ro
	}
	if d.TCP {
		d.client.Net = "tcp"
	} else {
		d.client.Net = "udp"
	}
}

func (d *DNSCrypt) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	d.setup()
	return d.client.Exchange(msg, d.resolver)
}

func (d *DNSCrypt) Close() error {
	d.resolver = nil
	d.client = nil
	return nil
}
