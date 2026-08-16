package process

import (
	"bytes"
	"runtime/debug"
	"strings"
)

func Stack(depth int) string {
	stack, lines := debug.Stack(), []string{}
	for _, line := range bytes.Split(stack, []byte{'\n'}) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && !bytes.Contains(line, []byte("stack.go")) {
			lines = append(lines, strings.Fields(strings.TrimSpace(string(line)))[0])
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
