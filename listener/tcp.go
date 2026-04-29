package listener

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

var (
	proxyHeader = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	proxyTable  = crc32.MakeTable(crc32.Castagnoli)
)

type TCPAddr struct {
	addr string
	port string
}

func (a TCPAddr) Network() string {
	return "tcp"
}

func (a TCPAddr) String() string {
	return net.JoinHostPort(a.addr, a.port)
}

type ProxyState int

const (
	ProxyStart ProxyState = iota
	ProxyAddr
	ProxyAttr
)

type TCPOptions struct {
	Reuse       bool
	ReadBuffer  int
	WriteBuffer int
	Callback    func(net.Conn)
	Proxy       func(*TCPConn, ProxyState) bool
	TLS         func(*TCPConn, string, []byte) bool
}

type TCPConn struct {
	options  *TCPOptions
	conn     *net.TCPConn
	proxyed  atomic.Bool
	tlsed    atomic.Bool
	hijacked bool
	local    *TCPAddr
	remote   *TCPAddr
	attrs    map[int][]byte
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	if err != nil {
		return 0, ustr.Wrap(err, "listener")
	}

	if !c.proxyed.Swap(true) {
		if n >= 16 && bytes.Equal(b[:12], proxyHeader) {
			size, offset := 16+int(binary.BigEndian.Uint16(b[14:])), 16
			if size < 16+12 || n < size || (b[12] != 0x20 && b[12] != 0x21) || (b[12] == 0x21 && b[13] != 0x11 && b[13] != 0x21) {
				c.Close()
				return 0, net.ErrClosed
			}

			if b[12] == 0x21 && c.options.Proxy != nil && c.options.Proxy(c, ProxyStart) {
				switch {
				case b[13]&0xf0 == 0x10 && offset <= n-12: // ipv4
					c.remote = &TCPAddr{addr: net.IPv4(b[16], b[17], b[18], b[19]).String(), port: ustr.Int(int(binary.BigEndian.Uint16(b[24:])))}
					c.local = &TCPAddr{addr: net.IPv4(b[20], b[21], b[22], b[23]).String(), port: ustr.Int(int(binary.BigEndian.Uint16(b[26:])))}
					offset += 12

				case offset <= n-36: // ipv6
					c.remote = &TCPAddr{addr: net.IP(b[16:32]).String(), port: ustr.Int(int(binary.BigEndian.Uint16(b[48:])))}
					c.local = &TCPAddr{addr: net.IP(b[32:48]).String(), port: ustr.Int(int(binary.BigEndian.Uint16(b[50:])))}
					offset += 36

				default:
					c.Close()
					return 0, net.ErrClosed
				}
				if !c.options.Proxy(c, ProxyAddr) {
					c.Close()
					return 0, net.ErrClosed
				}

				for offset <= size-3 { // tlvs
					if offset+3 > n {
						c.Close()
						return 0, net.ErrClosed
					}
					key, length := int(b[offset]), int(binary.BigEndian.Uint16(b[offset+1:]))
					if offset+3+length > size {
						c.Close()
						return 0, net.ErrClosed
					}
					if key != 4 {
						if c.attrs == nil {
							c.attrs = map[int][]byte{}
						}
						value := make([]byte, length)
						copy(value, b[offset+3:offset+3+length])
						c.attrs[key] = value
						if key == 3 && length >= 4 {
							copy(b[offset+3:], []byte{0, 0, 0, 0})
						}
					}
					offset += 3 + length
				}

				if c.attrs != nil {
					if value, exists := c.attrs[3]; exists {
						delete(c.attrs, 3)
						if crc32.Checksum(b[:size], proxyTable) != binary.BigEndian.Uint32(value) {
							c.local, c.remote, c.attrs = nil, nil, nil
							c.Close()
							return 0, net.ErrClosed
						}
					}
				}
				if !c.options.Proxy(c, ProxyAttr) {
					c.Close()
					return 0, net.ErrClosed
				}
			}

			if n > size {
				copy(b, b[size:n])
			}
			n -= size
		}
	}

	if n == 0 {
		n, err = c.conn.Read(b)
		if err != nil {
			return 0, ustr.Wrap(err, "listener")
		}
	}

	if !c.tlsed.Swap(true) && c.options.TLS != nil {
		if n >= 44 && b[0] == 0x16 && b[1] == 3 && b[2] >= 1 && b[5] == 1 && b[9] == 3 && b[10] >= 1 {
			if offset := 44 + int(b[43]); offset < n-1 {
				if length := int(binary.BigEndian.Uint16(b[offset:])); length%2 == 0 {
					offset += 2 + length
					if offset < n {
						offset += 1 + int(b[offset])
						if offset < n-1 {
							end := offset + 2 + int(binary.BigEndian.Uint16(b[offset:]))
							offset += 2
							end = min(end, n)
							for offset <= end-4 {
								key, length := int(binary.BigEndian.Uint16(b[offset:])), int(binary.BigEndian.Uint16(b[offset+2:]))
								if offset+4+length < end {
									if key == 0 && length >= 6 && b[offset+7] == 0 {
										cb := make([]byte, n)
										copy(cb, b[:n])
										if c.options.TLS(c, string(b[offset+9:offset+4+length]), cb) {
											c.hijacked = true
											return 0, net.ErrClosed
										}
										break
									}
								}
								offset += 4 + length
							}
						}
					}
				}
			}
		}
	}

	return n, ustr.Wrap(err, "listener")
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *TCPConn) Close() error {
	if c.hijacked {
		return nil
	}

	return c.conn.Close()
}

func (c *TCPConn) Close2() error {
	return c.conn.Close()
}

func (c *TCPConn) LocalAddr() net.Addr {
	if c.local != nil {
		return *c.local
	}

	return c.conn.LocalAddr()
}

func (c *TCPConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return *c.remote
	}

	return c.conn.RemoteAddr()
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *TCPConn) Attrs() map[int][]byte {
	return c.attrs
}

func (c *TCPConn) Attr(attr int) []byte {
	if c.attrs != nil {
		return c.attrs[attr]
	}

	return nil
}

type TCPListener struct {
	options  *TCPOptions
	listener *net.TCPListener
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.listener.AcceptTCP()
	if err != nil {
		return nil, ustr.Wrap(err, "listener")
	}
	conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3})
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

	return &TCPConn{options: l.options, conn: conn}, nil
}

func (l *TCPListener) Close() error {
	return l.listener.Close()
}

func (l *TCPListener) Addr() (addr net.Addr) {
	return l.listener.Addr()
}

func NewTCPListener(network, address string, options *TCPOptions) (listener *TCPListener, err error) {
	config := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			conn.Control(func(handle uintptr) {
				reuse(handle, options != nil && options.Reuse)
			})
			return nil
		}}
	clistener, err := config.Listen(context.Background(), network, address)
	if err != nil {
		return nil, ustr.Wrap(err, "listener")
	}

	return &TCPListener{options: options, listener: clistener.(*net.TCPListener)}, nil
}
