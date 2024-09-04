package process

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/rcache"
)

type TASK struct {
	Pid      int
	Threads  []int
	Names    map[int]string
	Captures []string
}

func Task(in string) (out []*TASK) {
	if matcher := rcache.Get(in); matcher != nil {
		if entries, err := filepath.Glob("/proc/[0-9]*"); err == nil {
			for _, entry := range entries {
				if content, err := os.ReadFile(filepath.Join(entry, "cmdline")); err == nil && len(content) != 0 {
					if captures := matcher.FindSubmatch(bytes.ReplaceAll(content, []byte{0}, []byte{' '})); captures != nil {
						pid, _ := strconv.Atoi(filepath.Base(entry))
						task := &TASK{Pid: pid}
						if len(captures) > 1 {
							for _, value := range captures[1:] {
								task.Captures = append(task.Captures, string(value))
							}
						}
						if entries, err := filepath.Glob(entry + "/task/[0-9]*"); err == nil {
							for _, entry := range entries {
								if value, err := strconv.Atoi(filepath.Base(entry)); err == nil && value != 0 {
									if value != pid {
										task.Threads = append(task.Threads, value)
									}
									if content, err := os.ReadFile(filepath.Join(entry, "comm")); err == nil {
										if task.Names == nil {
											task.Names = map[int]string{}
										}
										task.Names[value] = strings.TrimSpace(string(content))
									}
								}
							}
						}
						out = append(out, task)
					}
				}
			}
		}
	}
	return
}
