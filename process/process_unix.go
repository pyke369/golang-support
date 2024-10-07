package process

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

func Self() string {
	if path, err := filepath.Abs(os.Args[0]); err == nil {
		return path
	}
	return ""
}

func Exec(command string, extra ...map[string]any) (lines []string) {
	var (
		matcher *regexp.Regexp
		content []byte
	)

	timeout, combined, options, capture, separator := 10*time.Second, false, 0, false, ""
	if command = strings.TrimSpace(command); command == "" {
		return
	}
	if len(extra) > 0 {
		if value, ok := extra[0]["timeout"].(int); ok {
			timeout = time.Duration(max(1, min(60, value))) * time.Second
		}
		if value, ok := extra[0]["combined"].(bool); ok {
			combined = value
		}
	}

	parts := strings.Split(command, " ")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)

	if len(extra) > 0 {
		if value, ok := extra[0]["stdin"].(io.Reader); ok {
			cmd.Stdin = value
		}
		if value, ok := extra[0]["environ"].(map[string]string); ok {
			cmd.Env = cmd.Environ()
			for key, value := range value {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		if value, ok := extra[0]["dir"].(string); ok {
			cmd.Dir = value
		}
		if value, ok := extra[0]["options"].(string); ok {
			options = ustr.Options(value)
		}
		if value, ok := extra[0]["match"].(string); ok {
			matcher = rcache.Get(strings.TrimSpace(value))
			if value, ok := extra[0]["separator"].(string); ok {
				capture, separator = true, value
			}
		}
	}

	if combined {
		content, _ = cmd.CombinedOutput()
	} else {
		content, _ = cmd.Output()
	}

	if options&ustr.OptionJSON != 0 {
		var data any

		if json.Unmarshal(content, &data) != nil {
			return
		}
		content, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return
		}
		return strings.Split(string(content), "\n")
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = ustr.Transform(line, options)
		if line == "" && options&ustr.OptionEmpty != 0 {
			continue
		}
		if matcher != nil {
			captures := matcher.FindStringSubmatch(line)
			if captures == nil {
				continue
			}
			if capture && len(captures) > 1 {
				line = strings.Join(captures[1:], separator)
			}
		}
		lines = append(lines, line)
		if len(lines) != 0 && options&ustr.OptionFirst != 0 {
			return
		}
	}

	return
}
