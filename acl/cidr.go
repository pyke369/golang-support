package acl

import (
	"net/netip"
	"strconv"
	"strings"
)

func CIDR(in string, values []string) (pass bool, err error) {
	if len(values) == 0 {
		return false, nil
	}

	if value, err := netip.ParseAddrPort(in); err == nil {
		in = value.Addr().String()
	}
	remote, err := netip.ParseAddr(in)
	if err != nil {
		return false, err
	}

	remote = remote.Unmap().WithZone("")
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

		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return false, err
		}

		if prefix.Addr().Is4In6() {
			if bits := prefix.Bits(); bits >= 96 {
				if value, err := netip.ParsePrefix(prefix.Addr().Unmap().String() + "/" + strconv.Itoa(bits-96)); err == nil {
					prefix = value
				}
			}
		}
		if prefix.Contains(remote) {
			return true, nil
		}
	}

	return false, nil
}
