package net

import (
	"net"
	"net/netip"
	"strings"
)

var (
	v4reserved = []netip.Prefix{}
	v6reserved = []netip.Prefix{}
)

func init() {
	// https://www.iana.org/assignments/iana-ipv4-special-registry
	for _, prefix := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.31.196.0/24",
		"192.52.193.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"192.175.48.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"233.252.0.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
	} {
		v4reserved = append(v4reserved, netip.MustParsePrefix(prefix))
	}

	// https://www.iana.org/assignments/iana-ipv6-special-registry
	for _, prefix := range []string{
		"::/128",
		"::1/128",
		"::ffff:0:0/96",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"100:0:0:1::/64",
		"2001::/23",
		"2001:1::1/128",
		"2001:1::2/128",
		"2001:1::3/128",
		"2001:2::/48",
		"2001:3::/32",
		"2001:4:112::/48",
		"2001:10::/28",
		"2001:20::/28",
		"2001:30::/28",
		"2001:db8::/32",
		"2002::/16",
		"2620:4f:8000::/48",
		"3fff::/20",
		"5f00::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	} {
		v6reserved = append(v6reserved, netip.MustParsePrefix(prefix))
	}
}

func Address(in string) (out string) {
	out = in
	if value, _, err := net.SplitHostPort(in); err == nil {
		out = value
	}

	return
}

func Loopback(in string) (loopback bool, err error) {
	in = strings.TrimLeft(in, "*")
	value := net.ParseIP(Address(in))
	if value == nil {
		resolved, err := net.ResolveIPAddr("ip", Address(in))
		if err != nil {
			return false, err
		}
		value = resolved.IP
	}

	return value.IsLoopback(), nil
}

func Reserved(in netip.Addr) bool {
	in = in.Unmap()
	if in.Is4() {
		for _, prefix := range v4reserved {
			if prefix.Contains(in) {
				return true
			}
		}

	} else {
		for _, prefix := range v6reserved {
			if prefix.Contains(in) {
				return true
			}
		}
	}

	return false
}
