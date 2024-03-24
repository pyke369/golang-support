package acl

import (
	"net/netip"

	"github.com/pyke369/golang-support/uconfig"
)

func CIDR(in string, values []string, fallback bool) (match bool, index int) {
	if len(values) > 0 {
		if value, err := netip.ParseAddrPort(in); err == nil {
			in = value.Addr().String()
		}
		if remote, err := netip.ParseAddr(in); err == nil {
			for _, value := range values {
				if network, err := netip.ParsePrefix(value); err == nil {
					if network.Contains(remote) {
						return true, index
					}
				}
				index++
			}
		}
		return false, -1
	}
	return fallback, -1
}
func CIDRConfig(in string, config *uconfig.UConfig, path string, fallback bool) (match bool, index int) {
	return CIDR(in, config.GetStrings(path), fallback)
}
