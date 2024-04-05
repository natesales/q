package transport

import (
	"time"
)

func tlsTransport() *TLS {
	return &TLS{
		Common: Common{
			Server:    "dns.quad9.net:853",
			Timeout:   1 * time.Second,
			ReuseConn: false,
		},
	}
}
