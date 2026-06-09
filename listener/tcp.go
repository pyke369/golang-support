package listener

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"maps"
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
	hijacked atomic.Bool
	local    *TCPAddr
	remote   *TCPAddr
	attrs    map[int][]byte
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	if err != nil {
		return 0, err
	}

	// PROXYv2
	if c.options.Proxy != nil && !c.proxyed.Swap(true) {
		if n >= 16 && bytes.Equal(b[:12], proxyHeader) {
			size, offset := 16+int(binary.BigEndian.Uint16(b[14:])), 16
			if n < size || (b[12] != 0x20 && b[12] != 0x21) || (b[12] == 0x21 && b[13] != 0x11 && b[13] != 0x21) {
				c.Close()
				return 0, net.ErrClosed
			}

			if b[12] == 0x21 && c.options.Proxy(c, ProxyStart) {
				switch {
				case b[13] == 0x11 && offset <= size-12: // ipv4
					c.remote = &TCPAddr{
						addr: net.IPv4(b[offset], b[offset+1], b[offset+2], b[offset+3]).String(),
						port: ustr.Int(int(binary.BigEndian.Uint16(b[offset+8:]))),
					}
					c.local = &TCPAddr{
						addr: net.IPv4(b[offset+4], b[offset+5], b[offset+6], b[offset+7]).String(),
						port: ustr.Int(int(binary.BigEndian.Uint16(b[offset+10:]))),
					}
					offset += 12

				case b[13] == 0x21 && offset <= size-36: // ipv6
					c.remote = &TCPAddr{
						addr: net.IP(b[offset : offset+16]).String(),
						port: ustr.Int(int(binary.BigEndian.Uint16(b[offset+32:]))),
					}
					c.local = &TCPAddr{
						addr: net.IP(b[offset+16 : offset+32]).String(),
						port: ustr.Int(int(binary.BigEndian.Uint16(b[offset+34:]))),
					}
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
					if offset+3 > size {
						c.Close()
						return 0, net.ErrClosed
					}
					key, length := int(b[offset]), int(binary.BigEndian.Uint16(b[offset+1:]))
					if offset+3+length > size {
						c.Close()
						return 0, net.ErrClosed
					}
					if key != 4 { // NOOP
						if c.attrs == nil {
							c.attrs = map[int][]byte{}
						}
						value := make([]byte, length)
						copy(value, b[offset+3:offset+3+length])
						c.attrs[key] = value
						if key == 3 && length == 4 { // CRC32C
							copy(b[offset+3:], []byte{0, 0, 0, 0})
						}
					}
					offset += 3 + length
				}
				if c.attrs != nil {
					if value, exists := c.attrs[3]; exists { // CRC32C
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
			return 0, err
		}
	}

	// TLS
	if !c.tlsed.Swap(true) && c.options.TLS != nil {
		if n >= 44 && b[0] == 0x16 && b[1] == 3 && b[2] >= 1 { // TLS1.0+ handshake
			if b[5] == 1 { // ClientHello message
				if b[9] == 3 && b[10] >= 1 { // TLS1.0+ client
					offset := 43
					if length := int(b[43]); offset+1+length < n-1 { // ignore session-id
						offset += 1 + length
						if length := int(binary.BigEndian.Uint16(b[offset:])); length%2 == 0 && offset+2+length < n { // ignore cyphers
							offset += 2 + length
							if length := int(b[offset]); offset+1+length < n-1 { // ignore compression
								offset += 1 + length
								end := min(offset+2+int(binary.BigEndian.Uint16(b[offset:])), n)
								offset += 2
								for offset < end-4 { // extensions
									key, length := int(binary.BigEndian.Uint16(b[offset:])), int(binary.BigEndian.Uint16(b[offset+2:]))
									if key == 0x0000 { // SNI
										if offset+4+length < end {
											offset += 4
											if int(binary.BigEndian.Uint16(b[offset:])) == length-2 {
												offset += 2
												if b[offset] == 0 { // DNS hostname
													offset++
													if int(binary.BigEndian.Uint16(b[offset:])) == length-5 {
														offset += 2
														if c.options.TLS(c, string(b[offset:offset+length-5]), b[:n]) {
															c.hijacked.Store(true)
															return 0, net.ErrClosed
														}
													}
												}
											}
										}
										break
									}
									offset += 4 + length
								}
							}
						}
					}
				}
			}
		}
	}

	return n, err
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *TCPConn) Close() error {
	if c.hijacked.Load() {
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
	return maps.Clone(c.attrs)
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
		return nil, err
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

func NewTCPListener(network, address string, extra ...*TCPOptions) (listener *TCPListener, err error) {
	options := &TCPOptions{}
	if len(extra) != 0 && extra[0] != nil {
		options = extra[0]
	}
	config := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			conn.Control(func(handle uintptr) {
				reuse(handle, options.Reuse)
			})
			return nil
		},
	}
	clistener, err := config.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	return &TCPListener{options: options, listener: clistener.(*net.TCPListener)}, nil
}
