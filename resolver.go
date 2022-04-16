package main

import (
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// createQuery creates a slice of DNS queries
func createQuery(
	name string,
	chaos, dnssec, nsid bool,
	rrTypes []uint16,
	aaFlag, adFlag, cdFlag, rdFlag, raFlag, zFlag bool,
	udpBuffer uint16,
	clientSubnet string,
) []dns.Msg {
	var queries []dns.Msg

	// Query for each requested RR type
	for _, qType := range rrTypes {
		req := dns.Msg{}

		req.Authoritative = aaFlag
		req.AuthenticatedData = adFlag
		req.CheckingDisabled = cdFlag
		req.RecursionDesired = rdFlag
		req.RecursionAvailable = raFlag
		req.Zero = zFlag

		if dnssec || nsid || clientSubnet != "" {
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

			if clientSubnet != "" {
				addr := net.ParseIP(clientSubnet)
				if addr == nil {
					log.Fatalf("parsing IP address %s", clientSubnet)
				}

				ednsSubnet := &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Address:       addr,
					Family:        1, // IPv4
					SourceNetmask: 32,
				}

				// Set IPv6 family/mask
				if ednsSubnet.Address.To4() == nil {
					ednsSubnet.Family = 2 // IPv6
					ednsSubnet.SourceNetmask = 128
				}
				opt.Option = append(opt.Option, ednsSubnet)
			}
			req.Extra = append(req.Extra, opt)
		}

		var class uint16
		if chaos {
			class = dns.ClassCHAOS
		} else {
			class = dns.ClassINET
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
