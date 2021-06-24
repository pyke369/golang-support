package acl

import (
	_ "encoding/base64"
	"io/ioutil"
	"net"
	"strings"

	"github.com/pyke369/golang-support/uconfig"
)

// var encoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

func CIDR(input string, values []string) (match bool) {
	if len(values) > 0 {
		remote, _, err := net.SplitHostPort(input)
		if err != nil {
			remote = input
		}
		if remote := net.ParseIP(remote); remote != nil {
			for _, value := range values {
				_, network, _ := net.ParseCIDR(value)
				if network == nil {
					if address := net.ParseIP(value); address != nil {
						if address.To4() != nil {
							value += "/32"
						} else {
							value += "/128"
						}
						_, network, _ = net.ParseCIDR(value)
					}
				}
				if network != nil && network.Contains(remote) {
					return true
				}
			}
		}
		return false
	}
	return true
}
func CIDRConfig(input string, config *uconfig.UConfig, path string) bool {
	return CIDR(input, config.GetStrings(path))
}

func Password(input string, values []string) bool {
	if len(values) > 0 {
		if credentials := strings.Split(input, ":"); len(credentials) >= 2 {
			for _, value := range values {
				if parts := strings.Split(value, ":"); len(parts) >= 2 {
					if parts[0] == credentials[0] {
						if parts := strings.Split(parts[1], "$"); len(parts) >= 4 && parts[0] == "" && parts[1] == "6" && parts[2] != "" && parts[3] != "" {
						}
						break
					}
				}
			}
		}
	}
	return false
}
func PasswordConfig(input string, config *uconfig.UConfig, path string) bool {
	return Password(input, config.GetStrings(path))
}
func PasswordFile(input, path string) bool {
	lines := []string{}
	if content, err := ioutil.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if (len(line) >= 1 && line[0] != '#') || (len(line) >= 2 && line[0] != '/' && line[1] != '/') {
				lines = append(lines, line)
			}
		}
	}
	return Password(input, lines)
}
