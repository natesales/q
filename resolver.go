package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

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

// exchangeAll exchanges multiple DNS queries
func exchangeAll(queries []dns.Msg, txp *transport.Transport, isQUIC, sequential bool) ([]*dns.Msg, error) {
	var replies []*dns.Msg

	if sequential {
		for _, msg := range queries {
			reply, err := (*txp).Exchange(&msg)
			if err != nil {
				return nil, err
			}

			// Skip ID check if QUIC (https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1)
			if !isQUIC && !opts.NoIDCheck && reply.Id != msg.Id {
				return nil, fmt.Errorf("ID mismatch: expected %d, got %d", msg.Id, reply.Id)
			}

			replies = append(replies, reply)
		}
	} else {
		var wg sync.WaitGroup
		var lock sync.Mutex

		for _, msg := range queries {
			var errC chan error

			wg.Add(1)
			go func(m *dns.Msg) {
				defer wg.Done()
				reply, err := (*txp).Exchange(m)
				if err != nil {
					errC <- err
					return
				}

				// Skip ID check if QUIC (https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1)
				if !isQUIC && !opts.NoIDCheck && reply.Id != msg.Id {
					errC <- fmt.Errorf("ID mismatch: expected %d, got %d", msg.Id, reply.Id)
					return
				}

				lock.Lock()
				replies = append(replies, reply)
				lock.Unlock()
			}(&msg)

			select {
			case err := <-errC:
				return nil, err
			}
		}
		wg.Wait()
	}

	return replies, nil
}

// newTransport creates a new transport based on local options
func newTransport(server, protocol string, tlsConfig *tls.Config) (*transport.Transport, error) {
	var ts transport.Transport

	switch protocol {
	case "https", "http":
		if opts.ODoHProxy != "" {
			log.Debugf("Using ODoH transport with target %s proxy %s", server, opts.ODoHProxy)
			ts = &transport.ODoH{
				Target:    server,
				Proxy:     opts.ODoHProxy,
				TLSConfig: tlsConfig,
				ReuseConn: !opts.NoReuseConn,
			}
		} else {
			log.Debug("Using HTTP(s) transport")
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
	case "quic":
		log.Debug("Using QUIC transport")
		ts = &transport.QUIC{
			Server:          server,
			TLSConfig:       tlsConfig,
			NoPMTUD:         opts.QUICNoPMTUD,
			AddLengthPrefix: !opts.QUICNoLengthPrefix,
			ReuseConn:       !opts.NoReuseConn,
		}
	case "tls":
		log.Debug("Using TLS transport")
		ts = &transport.TLS{
			Server:    server,
			TLSConfig: tlsConfig,
			Timeout:   opts.Timeout,
			ReuseConn: !opts.NoReuseConn,
		}
	case "tcp":
		log.Debug("Using TCP transport")
		ts = &transport.Plain{
			Server:    server,
			PreferTCP: true,
			Timeout:   opts.Timeout,
			UDPBuffer: opts.UDPBuffer,
		}
	case "plain":
		log.Debug("Using UDP with TCP fallback")
		ts = &transport.Plain{
			Server:    server,
			PreferTCP: false,
			Timeout:   opts.Timeout,
			UDPBuffer: opts.UDPBuffer,
		}
	default:
		return nil, fmt.Errorf("unknown transport protocol %s", protocol)
	}

	return &ts, nil
}
