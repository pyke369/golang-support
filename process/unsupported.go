//go:build !linux

package process

import (
	"github.com/pyke369/golang-support/ustr"
)

type TASK struct {
	Pid      int
	Threads  []int
	Names    map[int]string
	Captures []string
}

func Task(in string) (out []*TASK) {
	return
}

func Affinity(pids, cores []int) error {
	return nil, ustr.Wrap(errors.ErrUnsupported, "process")
}
