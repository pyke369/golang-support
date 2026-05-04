//go:build linux

package uio

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/ustr"
	"golang.org/x/sys/unix"
)

var (
	serialSpeeds = map[int]uint32{
		50:      unix.B50,
		75:      unix.B75,
		110:     unix.B110,
		134:     unix.B134,
		150:     unix.B150,
		200:     unix.B200,
		300:     unix.B300,
		600:     unix.B600,
		1200:    unix.B1200,
		1800:    unix.B1800,
		2400:    unix.B2400,
		4800:    unix.B4800,
		9600:    unix.B9600,
		19200:   unix.B19200,
		38400:   unix.B38400,
		57600:   unix.B57600,
		115200:  unix.B115200,
		230400:  unix.B230400,
		460800:  unix.B460800,
		500000:  unix.B500000,
		576000:  unix.B576000,
		921600:  unix.B921600,
		1000000: unix.B1000000,
		1152000: unix.B1152000,
		1500000: unix.B1500000,
		2000000: unix.B2000000,
		2500000: unix.B2500000,
		3000000: unix.B3000000,
		3500000: unix.B3500000,
		4000000: unix.B4000000,
	}
	serialBits = map[byte]uint32{
		5: unix.CS5,
		6: unix.CS6,
		7: unix.CS7,
		8: unix.CS8,
	}
	serialParities = map[byte]uint32{
		'N': 0,
		'E': unix.PARENB,
		'O': unix.PARENB | unix.PARODD,
	}
	serialStops = map[byte]uint32{
		1: 0,
		2: unix.CSTOPB,
	}
)

type serialAddr struct {
	name string
}

func (a *serialAddr) Network() string {
	return "serial"
}

func (a *serialAddr) String() string {
	return a.name
}

type serial struct {
	handle    int
	control   bool
	local     *serialAddr
	remote    *serialAddr
	rdeadline time.Time
	wdeadline time.Time
}

func serialPath(path string) error {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ustr.Wrap(err, "uio")
	}
	if !strings.HasPrefix(target, "/dev/tty") && !strings.HasPrefix(target, "/dev/serial/") {
		return errors.New("uio: invalid device path")
	}

	return nil
}

func SerialProbe(path string) (active bool, err error) {
	if err := serialPath(path); err != nil {
		return false, ustr.Wrap(err, "uio")
	}

	handle, err := unix.Open(path, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, ustr.Wrap(err, "uio")
	}
	defer unix.Close(handle)

	state, err := unix.IoctlGetInt(handle, unix.TIOCMGET)
	if err != nil {
		return false, ustr.Wrap(err, "uio")
	}

	return state&unix.TIOCM_CTS != 0, nil
}

func SerialDial(path string, speed int, bit, parity, stop byte, extra ...string) (conn *serial, err error) {
	if err := serialPath(path); err != nil {
		return nil, ustr.Wrap(err, "uio")
	}

	handle, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ustr.Wrap(err, "uio")
	}

	if speed >= 0 {
		if _, exists := serialSpeeds[speed]; !exists {
			speed = 9600
		}
		if _, exists := serialBits[bit]; !exists {
			bit = 8
		}
		if _, exists := serialParities[parity]; !exists {
			parity = 'N'
		}
		if _, exists := serialStops[stop]; !exists {
			stop = 1
		}
		termios := unix.Termios{
			Iflag: unix.IGNPAR,
			Cflag: unix.CLOCAL | unix.CREAD | serialSpeeds[speed] | serialBits[bit] | serialParities[parity] | serialStops[stop],
		}
		termios.Cc[unix.VMIN] = 1
		if err := unix.IoctlSetTermios(handle, unix.TCSETS, &termios); err != nil {
			unix.Close(handle)
			return nil, ustr.Wrap(err, "uio")
		}
	}

	peer := ""
	if len(extra) > 0 {
		peer = extra[0]
	}

	return &serial{handle: handle, control: speed < 0, local: &serialAddr{name: path}, remote: &serialAddr{name: peer}}, nil
}

func (s *serial) Close() error {
	return unix.Close(s.handle)
}

func (s *serial) String() string {
	return s.local.String()
}

func (s *serial) Read(b []byte) (n int, err error) {
	if s.control {
		return 0, unsupported
	}

	set, timeout := []unix.PollFd{unix.PollFd{Fd: int32(s.handle), Events: unix.EPOLLIN}}, -1
	if !s.rdeadline.IsZero() {
		timeout = int(time.Until(s.rdeadline) / time.Millisecond)
	}
	s.rdeadline = time.Time{}

	if _, err := unix.Poll(set, timeout); err != nil {
		return 0, nil
	}
	if set[0].Revents == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	if set[0].Revents != unix.EPOLLIN {
		return 0, os.ErrClosed
	}

	return unix.Read(s.handle, b)
}

func (s *serial) Write(b []byte) (n int, err error) {
	if s.control {
		return 0, unsupported
	}

	set, timeout := []unix.PollFd{unix.PollFd{Fd: int32(s.handle), Events: unix.EPOLLOUT}}, -1
	if !s.wdeadline.IsZero() {
		timeout = int(time.Until(s.wdeadline) / time.Millisecond)
	}
	s.wdeadline = time.Time{}

	if _, err := unix.Poll(set, timeout); err != nil {
		return 0, nil
	}
	if set[0].Revents == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	if set[0].Revents != unix.EPOLLOUT {
		return 0, os.ErrClosed
	}

	return unix.Write(s.handle, b)
}

func (s *serial) LocalAddr() net.Addr {
	return s.local
}

func (s *serial) RemoteAddr() net.Addr {
	return s.remote
}

func (s *serial) SetDeadline(t time.Time) error {
	s.rdeadline, s.wdeadline = t, t
	return nil
}

func (s *serial) SetReadDeadline(t time.Time) error {
	s.rdeadline = t
	return nil
}

func (s *serial) SetWriteDeadline(t time.Time) error {
	s.wdeadline = t
	return nil
}

func (s *serial) GetControl() (control string, err error) {
	value, err := unix.IoctlGetInt(s.handle, unix.TIOCMGET)
	if err != nil {
		return "", ustr.Wrap(err, "uio")
	}
	if value&unix.TIOCM_CTS != 0 {
		control += " CTS"
	}
	if value&unix.TIOCM_DSR != 0 {
		control += " DSR"
	}
	if value&unix.TIOCM_CD != 0 {
		control += " CD"
	}
	if value&unix.TIOCM_RI != 0 {
		control += " RI"
	}

	return strings.TrimSpace(control), nil
}

func (s *serial) SetControl(control string) (err error) {
	fields := strings.Fields(strings.ToUpper(control))
	rts, dtr := slices.Contains(fields, "RTS"), slices.Contains(fields, "DTR")
	if rts || dtr {
		value, err := unix.IoctlGetInt(s.handle, unix.TIOCMGET)
		if err != nil {
			return ustr.Wrap(err, "uio")
		}
		if rts {
			value |= unix.TIOCM_RTS
		}
		if dtr {
			value |= unix.TIOCM_DTR
		}
		return unix.IoctlSetPointerInt(s.handle, unix.TIOCMSET, value)
	}

	return nil
}

func (s *serial) ClearControl(control string) (err error) {
	fields := strings.Fields(strings.ToUpper(control))
	rts, dtr := slices.Contains(fields, "RTS"), slices.Contains(fields, "DTR")
	if rts || dtr {
		value, err := unix.IoctlGetInt(s.handle, unix.TIOCMGET)
		if err != nil {
			return ustr.Wrap(err, "uio")
		}
		if rts {
			value &= ^unix.TIOCM_RTS
		}
		if dtr {
			value &= ^unix.TIOCM_DTR
		}
		return unix.IoctlSetPointerInt(s.handle, unix.TIOCMSET, value)
	}

	return nil
}
