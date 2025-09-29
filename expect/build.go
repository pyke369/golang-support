package expect

import (
	"sort"
	"strings"
)

func BuildXML(command string, parameters ...map[string]string) (out string) {
	out = "<" + command
	if len(parameters) > 1 {
		keys := []string{}
		for key := range parameters[1] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := parameters[1][key]
			out += ` ` + key + `="` + strings.ReplaceAll(value, `"`, `\"`) + `"`
		}
	}
	out += ">"
	if len(parameters) > 0 {
		keys := []string{}
		for key := range parameters[0] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := parameters[0][key]
			out += "<" + key
			if value == "" {
				out += "/>"
			} else {
				out += ">" + value + "</" + key + ">"
			}
		}
	}
	out += "</" + command + ">"

	return
}
