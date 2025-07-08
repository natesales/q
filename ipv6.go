package main

import (
	"fmt"
	"net"
)

func supportIPv6() (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue // Continue if we can't get addresses
		}

		for _, addr := range addrs {
			n, ok := addr.(*net.IPNet)
			if ok && n.IP.To4() == nil && n.IP.IsGlobalUnicast() {
				return true, nil
			}
		}
	}

	return false, nil
}
