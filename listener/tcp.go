package listener

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type TCPConn struct {
	options *TCPOptions
	conn    *net.TCPConn
}

func (c TCPConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}
func (c TCPConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}
func (c TCPConn) Close() error {
	return c.conn.Close()
}
func (c TCPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
func (c TCPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
func (c TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type TCPOptions struct {
	ReusePort   bool
	ReadBuffer  int
	WriteBuffer int
	Callback    func(net.Conn)
}

type TCPListener struct {
	options  *TCPOptions
	listener *net.TCPListener
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if raw, err := conn.SyscallConn(); err == nil {
		raw.Control(func(handle uintptr) {
			setOptions(int(handle))
		})
	}
	if l.options != nil {
		if l.options.ReadBuffer > 0 {
			conn.SetReadBuffer(l.options.ReadBuffer)
		}
		if l.options.WriteBuffer > 0 {
			conn.SetWriteBuffer(l.options.WriteBuffer)
		}
		if l.options.Callback != nil {
			l.options.Callback(conn)
		}
	}
	return TCPConn{options: l.options, conn: conn}, nil
}

func NewTCPListener(network, address string, options *TCPOptions) (listener *TCPListener, err error) {
	config := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			conn.Control(func(handle uintptr) {
				if err := syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					return
				}
				if options != nil && options.ReusePort {
					if err := syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						return
					}
				}
			})
			return nil
		}}
	clistener, err := config.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return &TCPListener{options: options, listener: clistener.(*net.TCPListener)}, nil
}

func (l *TCPListener) Close() error {
	return l.listener.Close()
}

func (l *TCPListener) Addr() (addr net.Addr) {
	return l.listener.Addr()
}
