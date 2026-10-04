package process

import (
	"bytes"
	"runtime/debug"
	"strings"
)

// for diagnostics only
func Stack(depth int) string {
	stack, lines := debug.Stack(), []string{}
	for _, line := range bytes.Split(stack, []byte{'\n'}) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && !bytes.Contains(line, []byte("stack.go")) {
			if fields := strings.Fields(strings.TrimSpace(string(line))); len(fields) > 0 {
				lines = append(lines, fields[0])
			}
		}
	}
	if len(lines) != 0 {
		lines = lines[1:]
	}
	if depth > 0 && depth < len(lines) {
		lines = lines[:depth]
	}

	return strings.Join(lines, "\n")
}
