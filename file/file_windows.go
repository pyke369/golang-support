//go:build windows

package file

import (
	"golang.org/x/sys/windows"
)

const O_NOFOLLOW = windows.O_FILE_FLAG_OPEN_REPARSE_POINT

func Space(in string) (total, free, occupied uint64) {
	occupied = 100
	path, err := windows.UTF16PtrFromString(in)
	if err != nil {
		return
	}
	if windows.GetDiskFreeSpaceEx(path, &free, &total, nil) == nil {
		free = min(total, free)
		if total != 0 {
			occupied = ((total - free) * 100) / total
		}
	}

	return
}
