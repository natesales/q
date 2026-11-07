//go:build !windows

package main

import (
	"github.com/miekg/dns"
)

// systemDNSServers returns the DNS servers from /etc/resolv.conf.
func systemDNSServers() []string {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return nil
	}
	return conf.Servers
}
