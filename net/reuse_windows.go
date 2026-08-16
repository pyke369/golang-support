//go:build windows

package net

import (
	"syscall"
)

func reuseAddr(handle uintptr) error {
	return nil
}

func reusePort(handle uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
