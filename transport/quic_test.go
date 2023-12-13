package transport

import "crypto/tls"

func quicTransport() *QUIC {
	return &QUIC{
		Server:          "dns.adguard.com:8853",
		PMTUD:           true,
		AddLengthPrefix: true,
		TLSConfig:       &tls.Config{NextProtos: []string{"doq"}},
	}
}
