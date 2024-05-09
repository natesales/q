package transport

func tlsTransport() *TLS {
	return &TLS{
		Common: Common{
			Server:    "dns.quad9.net:853",
			ReuseConn: false,
		},
	}
}
