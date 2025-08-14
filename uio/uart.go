//go:build !linux

package uio

import (
	"errors"
	"net"
	"time"
)

type uart struct{}

func UARTProbe(path string) bool {
	return false
}

func UARTDial(path string, speed int, parity, stop byte, timeout time.Duration) (conn *uart, err error) {
	return nil, errors.ErrUnsupported
}
func (s *uart) Read(b []byte) (n int, err error) {
	return 0, errors.ErrUnsupported
}
func (s *uart) Write(b []byte) (n int, err error) {
	return 0, errors.ErrUnsupported
}
func (s *uart) Close() error {
	return errors.ErrUnsupported
}
func (s *uart) Network() string {
	return "uart"
}
func (s *uart) String() string {
	return ""
}
func (s *uart) LocalAddr() net.Addr {
	return s
}
func (s *uart) RemoteAddr() net.Addr {
	return s
}
func (s *uart) SetDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
func (s *uart) SetReadDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
func (s *uart) SetWriteDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
