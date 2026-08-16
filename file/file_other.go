//go:build !windows

package file

import (
	"golang.org/x/sys/unix"
	"syscall"
)

const O_NOFOLLOW = syscall.O_NOFOLLOW

func Space(in string) (total, free, occupied uint64) {
	var info unix.Statfs_t

	occupied = 100
	if unix.Statfs(in, &info) == nil {
		total, free = info.Blocks*uint64(info.Bsize), info.Bavail*uint64(info.Bsize)
		free = min(total, free)
		if total != 0 {
			occupied = ((total - free) * 100) / total
		}
	}

	return
}
