package listener

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type TCPListener struct {
	*net.TCPListener
	read     int
	write    int
	callback func(*net.TCPConn)
}

func (this *TCPListener) Accept() (net.Conn, error) {
	connection, err := this.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if rconnection, err := connection.SyscallConn(); err == nil {
		rconnection.Control(
			func(handle uintptr) {
				syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
				syscall.SetsockoptInt(int(handle), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 60)
				syscall.SetsockoptInt(int(handle), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 10)
				syscall.SetsockoptInt(int(handle), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
			})
	}
	if this.read > 0 {
		connection.SetReadBuffer(this.read)
	}
	if this.write > 0 {
		connection.SetWriteBuffer(this.write)
	}
	if this.callback != nil {
		this.callback(connection)
	}
	return connection, nil
}

func NewTCPListener(network, address string, reuseport bool, read, write int, callback func(*net.TCPConn)) (listener *TCPListener, err error) {
	config := net.ListenConfig{
		Control: func(network, address string, connection syscall.RawConn) error {
			connection.Control(func(handle uintptr) {
				if err := syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					return
				}
				if reuseport {
					if err := syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						return
					}
				}
			})
			return nil
		}}
	if clistener, err := config.Listen(context.Background(), network, address); err != nil {
		return nil, err
	} else {
		return &TCPListener{clistener.(*net.TCPListener), read, write, callback}, nil
	}
}
