package process

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"

	"golang.org/x/sys/unix"
)

func Self() string {
	if path, err := filepath.Abs(os.Args[0]); err == nil {
		return path
	}
	return ""
}

func Exec(command string, extra ...map[string]any) (lines []string) {
	var matcher *regexp.Regexp

	timeout, options := 10*time.Second, 0
	if command = strings.TrimSpace(command); command == "" {
		return
	}
	if len(extra) > 0 {
		if value, ok := extra[0]["timeout"].(int); ok {
			timeout = time.Duration(max(1, min(60, value))) * time.Second
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
		if value, ok := extra[0]["match"].(string); ok {
			matcher = rcache.Get(strings.ToLower(strings.TrimSpace(value)))
		}
		if value, ok := extra[0]["options"].(string); ok {
			options = ustr.Options(value)
		}
	}
	content, _ := cmd.CombinedOutput()
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
		if (line == "" && options&ustr.OptionEmpty != 0) || (matcher != nil && !matcher.MatchString(line)) {
			continue
		}
		lines = append(lines, line)
		if len(lines) != 0 && options&ustr.OptionFirst != 0 {
			return
		}
	}
	return
}

func Pid(search string) (pid int, tasks []int) {
	if matcher := rcache.Get(search); matcher != nil {
		if entries, err := filepath.Glob("/proc/[0-9]*"); err == nil {
			for _, entry := range entries {
				if content, err := os.ReadFile(filepath.Join(entry, "cmdline")); err == nil && len(content) != 0 {
					if matcher.Match(bytes.ReplaceAll(content, []byte{0}, []byte{' '})) {
						pid, _ = strconv.Atoi(filepath.Base(entry))
						if entries, err := filepath.Glob(entry + "/task/[0-9]*"); err == nil {
							for _, entry := range entries {
								if value, err := strconv.Atoi(filepath.Base(entry)); err == nil && value != 0 && value != pid {
									tasks = append(tasks, value)
								}
							}
						}
						break
					}
				}
			}
		}
	}
	return
}

func Affinity(pids, cores []int) {
	set := unix.CPUSet{}
	for _, core := range cores {
		set.Set(core)
	}
	for _, pid := range pids {
		unix.SchedSetaffinity(pid, &set)
	}
}
