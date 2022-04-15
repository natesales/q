package main

import (
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func resolve(
	name string,
	chaos, dnssec bool,
	odohProxy string,
	upstream upstream.Upstream,
	rrTypes []uint16,
	aaFlag, adFlag, cdFlag, rdFlag, raFlag, zFlag bool,
	udpBuffer uint16,
) ([]dns.RR, time.Duration, error) {
	var answers []dns.RR
	queryStartTime := time.Now()

	// Query for each requested RR type
	for _, qType := range rrTypes {
		req := dns.Msg{}

		req.Authoritative = aaFlag
		req.AuthenticatedData = adFlag
		req.CheckingDisabled = cdFlag
		req.RecursionDesired = rdFlag
		req.RecursionAvailable = raFlag
		req.Zero = zFlag

		if dnssec {
			req.SetEdns0(udpBuffer, true)
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

		var err error
		var reply *dns.Msg
		// Use upstream exchange if no ODoH proxy is configured
		if odohProxy == "" {
			// Send question to server
			reply, err = upstream.Exchange(&req)
		} else {
			reply, err = odohQuery(req, upstream.Address(), odohProxy)
		}
		if err != nil {
			return nil, 0, err
		}

		answers = append(answers, reply.Answer...)
	}

	// Calculate total query time
	queryTime := time.Now().Sub(queryStartTime)

	return answers, queryTime, nil
}
