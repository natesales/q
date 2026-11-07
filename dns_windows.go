package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/log"
	"golang.org/x/sys/windows"
)

// systemDNSServers returns the DNS server addresses configured on active
// network interfaces, using GetAdaptersAddresses — the same API the Go
// standard library uses on Windows.
func systemDNSServers() []string {
	var b []byte
	l := uint32(15000) // Microsoft-recommended initial buffer size
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(
			syscall.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_PREFIX,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])),
			&l,
		)
		if err == nil {
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			log.Debugf("GetAdaptersAddresses: %v", err)
			return nil
		}
		if l <= uint32(len(b)) {
			return nil
		}
	}

	seen := make(map[string]bool)
	var servers []string
	for addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); addr != nil; addr = addr.Next {
		// Only use DNS servers from operational adapters.
		if addr.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for dns := addr.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			ipStr := ip.String()
			if ip.IsLinkLocalUnicast() {
				if ip.To4() != nil {
					// IPv4 link-local (169.254.x.x) has no interface binding — skip.
					continue
				}
				if dns.Address.Sockaddr != nil {
					sa6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(dns.Address.Sockaddr))
					if sa6.Scope_id != 0 {
						ipStr = fmt.Sprintf("%s%%%d", ipStr, sa6.Scope_id)
					}
				}
			}
			s := net.JoinHostPort(ipStr, "53")
			if !seen[s] {
				seen[s] = true
				servers = append(servers, s)
			}
		}
	}
	return servers
}
