package fqdn

import (
	"net"
	"os"
	"strings"
)

func FQDN() (hostname, address string) {
	if hostname, err := os.Hostname(); err == nil {
		if addresses, err := net.LookupHost(hostname); err == nil {
			for _, address := range addresses {
				if hostnames, err := net.LookupAddr(address); err == nil && len(hostnames) > 0 {
					for _, hostname := range hostnames {
						if strings.Count(hostname, ".") > 1 {
							hostname = strings.TrimSuffix(hostname, ".")
							addresses, _ = net.LookupHost(hostname)
							return hostname, addresses[0]
						}
					}
				}
			}
		}
		return hostname, "*"
	}
	return "unknown", "*"
}
