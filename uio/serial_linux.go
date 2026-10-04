//go:build linux

package uio

import (
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pyke369/golang-support/ustr"
	"golang.org/x/sys/unix"
)

var (
	serialSpeeds = map[int]uint32{
		1200:   unix.B1200,
		2400:   unix.B2400,
		4800:   unix.B4800,
		9600:   unix.B9600,
		19200:  unix.B19200,
		38400:  unix.B38400,
		57600:  unix.B57600,
		115200: unix.B115200,
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
	control bool
	local   *serialAddr
	remote  *serialAddr
	handle  *os.File
}

func SerialProbe(path string) (active bool, err error) {
	conn, err := SerialDial(path, -1, 0, 0, 0)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	control, err := conn.GetControl()
	if err != nil {
		return false, err
	}

	return strings.Contains(control, "CTS") || strings.Contains(control, "DSR"), nil
}

func SerialDial(path string, speed int, bit, parity, stop byte, extra ...string) (conn *serial, err error) {
	var info unix.Stat_t

	handle, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ustr.Wrap(err, "uio")
	}
	if err := unix.Fstat(handle, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFCHR {
		unix.Close(handle)
		return nil, errors.New("uio: invalid character device")
	}
	if _, err := unix.IoctlGetTermios(handle, unix.TCGETS); err != nil {
		unix.Close(handle)
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

	return &serial{control: speed < 0, local: &serialAddr{name: path}, remote: &serialAddr{name: peer}, handle: os.NewFile(uintptr(handle), path)}, nil
}

func (s *serial) Close() (err error) {
	return s.handle.Close()
}

func (s *serial) String() string {
	return s.local.String()
}

func (s *serial) Read(b []byte) (n int, err error) {
	if s.control {
		return 0, unsupported
	}

	return s.handle.Read(b)
}

func (s *serial) Write(b []byte) (n int, err error) {
	if s.control {
		return 0, unsupported
	}

	return s.handle.Write(b)
}

func (s *serial) LocalAddr() net.Addr {
	return s.local
}

func (s *serial) RemoteAddr() net.Addr {
	return s.remote
}

func (s *serial) SetDeadline(t time.Time) error {
	if s.control {
		return unsupported
	}

	return s.handle.SetDeadline(t)
}

func (s *serial) SetReadDeadline(t time.Time) error {
	if s.control {
		return unsupported
	}

	return s.handle.SetReadDeadline(t)
}

func (s *serial) SetWriteDeadline(t time.Time) error {
	if s.control {
		return unsupported
	}

	return s.handle.SetWriteDeadline(t)
}

func (s *serial) GetControl() (control string, err error) {
	handle := int(s.handle.Fd())
	value, err := unix.IoctlGetInt(handle, unix.TIOCMGET)
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
	lines := strings.Fields(strings.ToUpper(control))
	rts, dtr := slices.Contains(lines, "RTS"), slices.Contains(lines, "DTR")
	if rts || dtr {
		handle := int(s.handle.Fd())
		value, err := unix.IoctlGetInt(handle, unix.TIOCMGET)
		if err != nil {
			return ustr.Wrap(err, "uio")
		}
		if rts {
			value |= unix.TIOCM_RTS
		}
		if dtr {
			value |= unix.TIOCM_DTR
		}
		return unix.IoctlSetPointerInt(handle, unix.TIOCMSET, value)
	}

	return nil
}

func (s *serial) ClearControl(control string) (err error) {
	lines := strings.Fields(strings.ToUpper(control))
	rts, dtr := slices.Contains(lines, "RTS"), slices.Contains(lines, "DTR")
	if rts || dtr {
		handle := int(s.handle.Fd())
		value, err := unix.IoctlGetInt(handle, unix.TIOCMGET)
		if err != nil {
			return ustr.Wrap(err, "uio")
		}
		if rts {
			value &= ^unix.TIOCM_RTS
		}
		if dtr {
			value &= ^unix.TIOCM_DTR
		}
		return unix.IoctlSetPointerInt(handle, unix.TIOCMSET, value)
	}

	return nil
}
