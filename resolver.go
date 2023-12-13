package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
)

// createQuery creates a slice of DNS queries
func createQuery(opts cli.Flags, rrTypes []uint16) []dns.Msg {
	var queries []dns.Msg

	// Query for each requested RR type
	for _, qType := range rrTypes {
		req := dns.Msg{}

		if opts.ID != -1 {
			req.Id = uint16(opts.ID)
		} else {
			req.Id = dns.Id()
		}
		req.Authoritative = opts.AuthoritativeAnswer
		req.AuthenticatedData = opts.AuthenticData
		req.CheckingDisabled = opts.CheckingDisabled
		req.RecursionDesired = opts.RecursionDesired
		req.RecursionAvailable = opts.RecursionAvailable
		req.Zero = opts.Zero
		req.Truncated = opts.Truncated

		if opts.DNSSEC || opts.NSID || opts.Pad || opts.ClientSubnet != "" || opts.Cookie != "" {
			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Class:  opts.UDPBuffer,
					Rrtype: dns.TypeOPT,
				},
			}

			if opts.DNSSEC {
				opt.SetDo()
			}

			if opts.NSID {
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{
					Code: dns.EDNS0NSID,
				})
			}

			if opts.Pad {
				paddingOpt := new(dns.EDNS0_PADDING)

				msgLen := req.Len()
				padLen := 128 - msgLen%128

				// Truncate padding to fit in UDP buffer
				if msgLen+padLen > int(opt.UDPSize()) {
					padLen = int(opt.UDPSize()) - msgLen
					if padLen < 0 { // Stop padding
						padLen = 0
					}
				}

				log.Debugf("Padding with %d bytes", padLen)
				paddingOpt.Padding = make([]byte, padLen)
				opt.Option = append(opt.Option, paddingOpt)
			}

			if opts.ClientSubnet != "" {
				ip, ipNet, err := net.ParseCIDR(opts.ClientSubnet)
				if err != nil {
					log.Fatalf("parsing subnet %s", opts.ClientSubnet)
				}
				mask, _ := ipNet.Mask.Size()
				log.Debugf("EDNS0 client subnet %s/%d", ip, mask)

				ednsSubnet := &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Address:       ip,
					Family:        1, // IPv4
					SourceNetmask: uint8(mask),
				}

				if ednsSubnet.Address.To4() == nil {
					ednsSubnet.Family = 2 // IPv6
				}
				opt.Option = append(opt.Option, ednsSubnet)
			}

			if opts.Cookie != "" {
				cookie := &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: opts.Cookie,
				}
				opt.Option = append(opt.Option, cookie)
			}

			req.Extra = append(req.Extra, opt)
		}

		req.Question = []dns.Question{{
			Name:   dns.Fqdn(opts.Name),
			Qtype:  qType,
			Qclass: opts.Class,
		}}

		queries = append(queries, req)
	}
	return queries
}

// newTransport creates a new transport based on local options
func newTransport(server string, transportType transport.Type, tlsConfig *tls.Config) (*transport.Transport, error) {
	var ts transport.Transport

	switch transportType {
	case transport.TypeHTTP:
		if opts.ODoHProxy != "" {
			log.Debugf("Using ODoH transport with target %s proxy %s", server, opts.ODoHProxy)
			ts = &transport.ODoH{
				Target:    server,
				Proxy:     opts.ODoHProxy,
				TLSConfig: tlsConfig,
				ReuseConn: opts.ReuseConn,
			}
		} else {
			log.Debugf("Using HTTP(s) transport: %s", server)
			ts = &transport.HTTP{
				Server:    server,
				TLSConfig: tlsConfig,
				UserAgent: opts.HTTPUserAgent,
				Method:    opts.HTTPMethod,
				Timeout:   opts.Timeout,
				HTTP3:     opts.HTTP3,
				NoPMTUd:   !opts.PMTUD,
				ReuseConn: opts.ReuseConn,
			}
		}
	case transport.TypeDNSCrypt:
		log.Debugf("Using DNSCrypt transport: %s", server)
		if strings.HasPrefix(server, "sdns://") {
			log.Traceln("Using provided DNS stamp for DNSCrypt")
			ts = &transport.DNSCrypt{
				ServerStamp: server,
				TCP:         opts.DNSCryptTCP,
				Timeout:     opts.Timeout,
				UDPSize:     opts.DNSCryptUDPSize,
				ReuseConn:   opts.ReuseConn,
			}
		} else {
			log.Traceln("Using manual DNSCrypt configuration")
			ts = &transport.DNSCrypt{
				TCP:          opts.DNSCryptTCP,
				Timeout:      opts.Timeout,
				UDPSize:      opts.DNSCryptUDPSize,
				ReuseConn:    opts.ReuseConn,
				Server:       server,
				PublicKey:    opts.DNSCryptPublicKey,
				ProviderName: opts.DNSCryptProvider,
			}
		}
	case transport.TypeQUIC:
		log.Debugf("Using QUIC transport: %s", server)

		tc := tlsConfig.Clone()
		tlsConfig.NextProtos = opts.QUICALPNTokens

		ts = &transport.QUIC{
			Server:          server,
			TLSConfig:       tc,
			PMTUD:           opts.PMTUD,
			AddLengthPrefix: opts.QUICLengthPrefix,
			ReuseConn:       opts.ReuseConn,
		}
	case transport.TypeTLS:
		log.Debugf("Using TLS transport: %s", server)
		ts = &transport.TLS{
			Server:    server,
			TLSConfig: tlsConfig,
			Timeout:   opts.Timeout,
			ReuseConn: opts.ReuseConn,
		}
	case transport.TypeTCP:
		log.Debugf("Using TCP transport: %s", server)
		ts = &transport.Plain{
			Server:    server,
			PreferTCP: true,
			Timeout:   opts.Timeout,
			UDPBuffer: opts.UDPBuffer,
		}
	case transport.TypePlain:
		log.Debugf("Using UDP with TCP fallback: %s", server)
		ts = &transport.Plain{
			Server:    server,
			PreferTCP: false,
			Timeout:   opts.Timeout,
			UDPBuffer: opts.UDPBuffer,
		}
	default:
		return nil, fmt.Errorf("unknown transport protocol %s", transportType)
	}

	return &ts, nil
}
