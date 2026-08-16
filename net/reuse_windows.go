//go:build windows

package net

import (
	"syscall"
)

func reuseAddr(handle uintptr) {
	syscall.SetsockoptInt(syscall.Handle(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func reusePort(handle uintptr) {
}
