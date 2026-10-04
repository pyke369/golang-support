package process

import (
	"bytes"
	"runtime/debug"
	"strings"
)

// for diagnostics only
func Stack(depth int, extra ...[]string) []string {
	exclude := map[string]struct{}{"process/stack.go": struct{}{}}
	if len(extra) != 0 {
		for _, value := range extra[0] {
			exclude[value] = struct{}{}
		}
	}

	stack, lines := debug.Stack(), []string{}
	for _, line := range bytes.Split(stack, []byte{'\n'}) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			line := strings.TrimSpace(string(line))
			if fields := strings.Fields(line); len(fields) > 0 {
				include := true
				for value := range exclude {
					if strings.Contains(line, value) {
						include = false
						break
					}
				}
				if include {
					lines = append(lines, fields[0])
				}
			}
		}
	}
	if len(lines) != 0 {
		lines = lines[1:]
	}
	if depth > 0 && depth < len(lines) {
		lines = lines[:depth]
	}

	return lines
}
