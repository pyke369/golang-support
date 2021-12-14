package multiflag

import (
	"strings"
)

type Multiflag [][2]string

func (m *Multiflag) String() string {
	return ""
}

func (m *Multiflag) Set(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) >= 2 {
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(strings.Join(parts[1:], ":"))
		if len(key) > 0 && len(value) > 0 {
			*m = append(*m, [2]string{key, value})
		}
	}
	return nil
}
