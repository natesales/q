package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/natesales/q/transport"
)

// createQuery creates a slice of DNS queries
func createQuery(
	name string,
	dnssec, nsid bool,
	class uint16,
	rrTypes []uint16,
	aaFlag, adFlag, cdFlag, rdFlag, raFlag, zFlag, tcFlag bool,
	udpBuffer uint16,
	clientSubnet string,
	pad bool,
	id int,
) []dns.Msg {
	var queries []dns.Msg

	// Query for each requested RR type
	for _, qType := range rrTypes {
		req := dns.Msg{}

		if id != -1 {
			req.Id = uint16(id)
		} else {
			req.Id = dns.Id()
		}
		req.Authoritative = aaFlag
		req.AuthenticatedData = adFlag
		req.CheckingDisabled = cdFlag
		req.RecursionDesired = rdFlag
		req.RecursionAvailable = raFlag
		req.Zero = zFlag
		req.Truncated = tcFlag

		if dnssec || nsid || pad || clientSubnet != "" {
			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Class:  udpBuffer,
					Rrtype: dns.TypeOPT,
				},
			}

			if dnssec {
				opt.SetDo()
			}

			if nsid {
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{
					Code: dns.EDNS0NSID,
				})
			}

			if pad {
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

			if clientSubnet != "" {
				ip, ipNet, err := net.ParseCIDR(clientSubnet)
				if err != nil {
					log.Fatalf("parsing subnet %s", clientSubnet)
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
			req.Extra = append(req.Extra, opt)
		}

		req.Question = []dns.Question{{
			Name:   dns.Fqdn(name),
			Qtype:  qType,
			Qclass: class,
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
				ReuseConn: !opts.NoReuseConn,
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
				NoPMTUd:   opts.QUICNoPMTUD,
				ReuseConn: !opts.NoReuseConn,
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
				ReuseConn:   !opts.NoReuseConn,
			}
		} else {
			log.Traceln("Using manual DNSCrypt configuration")
			ts = &transport.DNSCrypt{
				TCP:          opts.DNSCryptTCP,
				Timeout:      opts.Timeout,
				UDPSize:      opts.DNSCryptUDPSize,
				ReuseConn:    !opts.NoReuseConn,
				Server:       server,
				PublicKey:    opts.DNSCryptPublicKey,
				ProviderName: opts.DNSCryptProvider,
			}
		}
	case transport.TypeQUIC:
		log.Debugf("Using QUIC transport: %s", server)
		ts = &transport.QUIC{
			Server:          server,
			TLSConfig:       tlsConfig,
			NoPMTUD:         opts.QUICNoPMTUD,
			AddLengthPrefix: !opts.QUICNoLengthPrefix,
			ReuseConn:       !opts.NoReuseConn,
		}
	case transport.TypeTLS:
		log.Debugf("Using TLS transport: %s", server)
		ts = &transport.TLS{
			Server:    server,
			TLSConfig: tlsConfig,
			Timeout:   opts.Timeout,
			ReuseConn: !opts.NoReuseConn,
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
