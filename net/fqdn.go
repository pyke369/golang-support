package net

import (
	"context"
	"net"
	"os"
	"slices"
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
				if hostnames, err := resolver.LookupAddr(ctx, address); err == nil {
					for _, hostname := range hostnames {
						hostname = strings.TrimSuffix(hostname, ".")
						if addresses, err := resolver.LookupHost(ctx, hostname); err == nil {
							if slices.Contains(addresses, address) {
								return hostname, address
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
