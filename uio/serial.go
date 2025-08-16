//go:build !linux

package uio

import (
	"errors"
	"net"
	"time"
)

type serial struct{}

func SerialProbe(path string) (active bool, err error) {
	return false, errors.ErrUnsupported
}

func SerialDial(path string, speed int, bit, parity, stop byte, extra ...string) (conn *serial, err error) {
	return nil, errors.ErrUnsupported
}
func (s *serial) Read(b []byte) (n int, err error) {
	return 0, errors.ErrUnsupported
}
func (s *serial) Write(b []byte) (n int, err error) {
	return 0, errors.ErrUnsupported
}
func (s *serial) Close() error {
	return errors.ErrUnsupported
}
func (s *serial) Network() string {
	return "unsupported"
}
func (s *serial) String() string {
	return ""
}
func (s *serial) LocalAddr() net.Addr {
	return s
}
func (s *serial) RemoteAddr() net.Addr {
	return s
}
func (s *serial) SetDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
func (s *serial) SetReadDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
func (s *serial) SetWriteDeadline(t time.Time) error {
	return errors.ErrUnsupported
}
func (s *serial) GetControl() (control string, err error) {
	return "", errors.ErrUnsupported
}
func (s *serial) SetControl(control string) (err error) {
	return errors.ErrUnsupported
}
func (s *serial) ClearControl(control string) (err error) {
	return errors.ErrUnsupported
}
