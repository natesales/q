package main

import (
	"crypto/tls"
	"fmt"
	"net"

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
) []dns.Msg {
	var queries []dns.Msg

	// Query for each requested RR type
	for _, qType := range rrTypes {
		req := dns.Msg{}

		req.Id = dns.Id()
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

// query performs a DNS query and returns the reply
func query(msg dns.Msg, server, protocol string, tlsConfig *tls.Config) (*dns.Msg, error) {
	var reply *dns.Msg
	var err error

	switch protocol {
	case "https", "http":
		if opts.ODoHProxy != "" {
			log.Debugf("Using ODoH transport with target %s proxy %s", server, opts.ODoHProxy)
			reply, err = transport.ODoH(msg, server, opts.ODoHProxy)
		} else {
			log.Debug("Using HTTP(s) transport")
			reply, err = transport.HTTP(&msg, tlsConfig, server, opts.HTTPUserAgent, opts.HTTPMethod, opts.Timeout, opts.HandshakeTimeout, opts.HTTP3, opts.QUICNoPMTUD)
		}
	case "quic":
		log.Debug("Using QUIC transport")
		reply, err = transport.QUIC(&msg, server, tlsConfig, opts.QUICDialTimeout, opts.HandshakeTimeout, opts.QUICOpenStreamTimeout, opts.QUICNoPMTUD)
	case "tls":
		log.Debug("Using TLS transport")
		reply, err = transport.TLS(&msg, server, tlsConfig, opts.TCPDialTimeout)
	case "tcp":
		log.Debug("Using TCP transport")
		reply, err = transport.Plain(&msg, server, true, opts.Timeout, opts.UDPBuffer)
	case "plain":
		log.Debug("Using UDP with TCP fallback")
		reply, err = transport.Plain(&msg, server, false, opts.Timeout, opts.UDPBuffer)
	default:
		return nil, fmt.Errorf("unknown transport protocol %s", protocol)
	}
	return reply, err
}
