package acl

import (
	"net/netip"

	"github.com/pyke369/golang-support/uconfig"
)

func CIDR(in string, values []string) bool {
	if len(values) == 0 {
		return false
	}

	if value, err := netip.ParseAddrPort(in); err == nil {
		in = value.Addr().String()
	}
	if remote, err := netip.ParseAddr(in); err == nil {
		remote = remote.Unmap()
		for _, value := range values {
			if network, err := netip.ParsePrefix(value); err == nil {
				// TODO Unmap() network.Addr()?
				if network.Contains(remote) {
					return true
				}
			}
		}
	}

	return false
}

func CIDRConfig(in string, config *uconfig.UConfig, path string) bool {
	return CIDR(in, config.Strings(path))
}
