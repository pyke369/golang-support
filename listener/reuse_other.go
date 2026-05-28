//go:build !windows

package listener

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func reuse(handle uintptr, port bool) {
	syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if port {
		syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}
}
