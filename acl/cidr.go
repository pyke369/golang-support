package acl

import (
	"net/netip"
	"strconv"

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
			if prefix, err := netip.ParsePrefix(value); err == nil {
				if prefix.Addr().Is4In6() {
					if bits := prefix.Bits(); bits >= 96 {
						if value, err := netip.ParsePrefix(prefix.Addr().Unmap().String() + "/" + strconv.Itoa(bits-96)); err == nil {
							prefix = value
						}
					}
				}
				if prefix.Contains(remote) {
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
