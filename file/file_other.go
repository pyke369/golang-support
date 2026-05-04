//go:build !windows

package file

import "syscall"

const O_NOFOLLOW = syscall.O_NOFOLLOW
