package expect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"regexp"
	"sort"
	"strings"
)

var matcher = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)

func BuildXML(command string, extra ...any) (out string, err error) {
	var b bytes.Buffer

	if !matcher.MatchString(command) {
		return "", errors.New("expect: invalid command")
	}
	b.WriteString("<" + command)
	if len(extra) > 1 {
		if attributes, ok := extra[1].(map[string]string); ok {
			keys := []string{}
			for key := range attributes {
				if !matcher.MatchString(key) {
					return "", errors.New("expect: invalid command attribute")
				}
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				b.WriteString(" " + key + `="`)
				xml.EscapeText(&b, []byte(attributes[key]))
				b.WriteString(`"`)
			}
		}
	}
	b.WriteString(">\n")

	if len(extra) > 0 {
		if value, ok := extra[0].(string); ok {
			if value := strings.TrimSpace(value); value != "" {
				b.WriteString(strings.ReplaceAll(value, "><", ">\n<"))
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("</" + command + ">\n")

	var unused any
	if err := xml.Unmarshal(b.Bytes(), &unused); err != nil {
		return "", err
	}

	return b.String(), nil
}
