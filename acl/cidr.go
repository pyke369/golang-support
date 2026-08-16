package acl

import (
	"net/netip"
	"strconv"
	"strings"

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
			value = strings.TrimSpace(value)
			if _, err := netip.ParsePrefix(value); err != nil {
				if addr, err := netip.ParseAddr(value); err == nil {
					if addr.Is4() {
						value += "/32"

					} else {
						value += "/128"
					}
				}
			}
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
