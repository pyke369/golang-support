package expect

import (
	"encoding/xml"
	"regexp"
	"sort"
	"strings"

	j "github.com/pyke369/golang-support/jsonrpc"
)

var matcher = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)

func BuildXML(command string, parameters ...map[string]string) (out string) {
	var b strings.Builder

	if !matcher.MatchString(command) {
		return
	}
	b.WriteString("<" + command)
	if len(parameters) > 1 {
		keys := []string{}
		for key := range parameters[1] {
			if !matcher.MatchString(key) {
				return
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b.WriteString(` ` + key + `="`)
			xml.EscapeText(&b, []byte(parameters[1][key]))
			b.WriteString(`"`)
		}
	}
	b.WriteString(">\n")

	if len(parameters) > 0 {
		keys := []string{}
		for key := range parameters[0] {
			if !matcher.MatchString(key) {
				return
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := parameters[0][key]
			b.WriteString(`<` + key)
			if value == "" {
				b.WriteString("/>\n")

			} else {
				b.WriteString(">\n")
				raw := false
				if len(parameters) > 2 {
					if value, ok := parameters[2]["raw"]; ok && j.Boolean(value) {
						raw = true
					}
				}
				if raw && !strings.Contains(value, "</"+key+">") && !strings.Contains(value, "]]>]]>") {
					b.WriteString(value)

				} else {
					xml.EscapeText(&b, []byte(value))
				}
				b.WriteString("\n</" + key + ">\n")
			}
		}
	}

	b.WriteString("</" + command + ">\n")

	return b.String()
}
