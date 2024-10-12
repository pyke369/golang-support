package multiflag

import "strings"

type Multiflag [][2]string

func (m *Multiflag) Set(value string) error {
	if parts := strings.SplitN(value, ":", 2); len(parts) == 2 {
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if key != "" && value != "" {
			*m = append(*m, [2]string{key, value})
		}
	}
	return nil
}

func (m *Multiflag) String() string {
	return ""
}
