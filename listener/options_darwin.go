//go:build darwin

package listener

import "syscall"

func setOptions(handle int) {
	syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	syscall.SetsockoptInt(handle, syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, 30)
	syscall.SetsockoptInt(handle, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 10)
	syscall.SetsockoptInt(handle, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
}
