//go:build windows

package file

import (
	"golang.org/x/sys/windows"
)

const O_NOFOLLOW = 0

func Space(in string) (total, free, occupied uint64) {
	occupied = 100
	if windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(in), &free, &total, nil) == nil {
		if total != 0 {
			occupied = ((total - free) * 100) / total
		}
	}

	return
}
