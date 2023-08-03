package transport

import "crypto/tls"

func quicTransport() *QUIC {
	return &QUIC{
		Server:          "dns.adguard.com:8853",
		NoPMTUD:         false,
		AddLengthPrefix: true,
		TLSConfig:       &tls.Config{NextProtos: []string{"doq"}},
	}
}
