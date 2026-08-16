//go:build !windows

package net

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func reuseAddr(handle uintptr) error {
	return syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func reusePort(handle uintptr) error {
	return syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
