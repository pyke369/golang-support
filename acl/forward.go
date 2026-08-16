package acl

import (
	"net"
	"net/netip"
	"strings"
)

func Forward(remote, forward string, trusted []string) (out string) {
	if !CIDR(remote, trusted) {
		return remote
	}

	values := strings.Split(forward, ",")
	for index := len(values) - 1; index >= 0; index-- {
		value := strings.TrimSpace(values[index])
		if _, err := netip.ParseAddr(value); err == nil {
			if !CIDR(value, trusted) {
				out = value
				break
			}
		}
	}
	if out == "" && len(values) != 0 {
		value := strings.TrimSpace(values[0])
		if _, err := netip.ParseAddr(value); err == nil {
			out = strings.TrimSpace(value)
		}
	}

	if out != "" {
		if _, port, err := net.SplitHostPort(remote); err == nil {
			out = net.JoinHostPort(out, port)
		}

	} else {
		out = remote
	}

	return
}
