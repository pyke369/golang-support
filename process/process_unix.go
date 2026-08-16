package process

import (
	"context"
	"encoding/json"
	"errors"
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

func Exec(command string, params []string, extra ...map[string]any) (lines []string, err error) {
	var (
		matcher *regexp.Regexp
		content []byte
	)

	timeout, combined, options, capture, separator := 10*time.Second, false, 0, false, ""
	if command = strings.TrimSpace(command); command == "" || !filepath.IsAbs(command) {
		return nil, errors.New("process: invalid command")
	}

	if len(extra) > 0 {
		if value, ok := extra[0]["timeout"].(int); ok {
			timeout = time.Duration(max(1, min(60, value))) * time.Second
		}
		if value, ok := extra[0]["combined"].(bool); ok {
			combined = value
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, params...)

	if len(extra) > 0 {
		if value, ok := extra[0]["stdin"].(io.Reader); ok {
			cmd.Stdin = value
		}
		if value, ok := extra[0]["environ"].(map[string]string); ok {
			cmd.Env = []string{}
			matcher := rcache.Get(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
			for key, value := range value {
				if matcher.MatchString(key) && !strings.Contains(value, "\x00") {
					cmd.Env = append(cmd.Env, key+"="+value)
				}
			}
		}
		if value, ok := extra[0]["dir"].(string); ok && filepath.IsAbs(value) {
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
		if content, err = cmd.CombinedOutput(); err != nil {
			return nil, err
		}

	} else {
		if content, err = cmd.Output(); err != nil {
			return nil, err
		}
	}

	if options&ustr.OptionJSON != 0 {
		var data any

		if err := json.Unmarshal(content, &data); err != nil {
			return nil, err
		}
		content, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, err
		}
		return strings.Split(string(content), "\n"), nil
	}

	for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
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
