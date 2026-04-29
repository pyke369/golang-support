package fqdn

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
)

func FQDN() (hostname, address string) {
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	if hostname, err := os.Hostname(); err == nil {
		if addresses, err := resolver.LookupHost(ctx, hostname); err == nil {
			for _, address := range addresses {
				if hostnames, err := resolver.LookupAddr(ctx, address); err == nil && len(hostnames) > 0 {
					for _, hostname := range hostnames {
						if strings.Count(hostname, ".") > 1 {
							hostname = strings.TrimSuffix(hostname, ".")
							if addresses, err := resolver.LookupHost(ctx, hostname); err == nil && len(addresses) != 0 {
								return hostname, addresses[0]
							}
						}
					}
				}
			}
		}
		return hostname, "*"
	}
	return "unknown", "*"
}
