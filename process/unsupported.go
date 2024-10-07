//go:build !linux

package process

type TASK struct {
	Pid      int
	Threads  []int
	Names    map[int]string
	Captures []string
}

func Task(in string) (out []*TASK) {
	// noop
	return
}

func Affinity(pids, cores []int) {
	// noop
}
