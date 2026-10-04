package acl

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

func Forward(remote, forward string, trusted []string) (out string, err error) {
	if forward = strings.TrimSpace(forward); forward == "" {
		return remote, nil
	}
	if pass, err := CIDR(remote, trusted); err != nil || !pass {
		return remote, nil
	}

	values := strings.Split(forward, ",")
	values = values[max(0, len(values)-10):]
	for index := len(values) - 1; index >= 0; index-- {
		value := strings.TrimSpace(values[index])
		if _, err := netip.ParseAddr(value); err != nil {
			return "", errors.New("acl: malformed forward")
		}
		if pass, err := CIDR(value, trusted); err != nil || !pass {
			out = value
			break
		}
	}
	if out != "" {
		if _, port, err := net.SplitHostPort(remote); err == nil {
			out = net.JoinHostPort(out, port)
		}

	} else {
		if len(values) > 0 {
			out = strings.TrimSpace(values[0])

		} else {
			out = remote
		}
	}

	return
}
