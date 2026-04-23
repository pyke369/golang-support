//go:build windows

package listener

import (
	"syscall"
)

func reuse(handle uintptr, port bool) {
	if port {
		syscall.SetsockoptInt(syscall.Handle(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}
}
