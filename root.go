package main

import (
	"net/http"

	"github.com/miekg/dns"
)

func getRootHints() (ip4s, ip6s []string, err error) {
	resp, err := http.Get("https://www.internic.net/domain/named.root")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	p := dns.NewZoneParser(resp.Body, "", "")

	for rr, ok := p.Next(); ok; rr, ok = p.Next() {
		if a, ok := rr.(*dns.A); ok {
			ip4s = append(ip4s, a.A.String())
		} else if a, ok := rr.(*dns.AAAA); ok {
			ip6s = append(ip6s, a.AAAA.String())
		}
	}
	return
}
