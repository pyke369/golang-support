//go:build linux

package uio

import (
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	speeds = map[int]uint32{
		0:       unix.B9600,
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
	bits = map[byte]uint32{
		0: unix.CS8,
		5: unix.CS5,
		6: unix.CS6,
		7: unix.CS7,
		8: unix.CS8,
	}
	parities = map[byte]uint32{
		0:   0,
		'N': 0,
		'E': unix.PARENB,
		'O': unix.PARENB | unix.PARODD,
	}
	stops = map[byte]uint32{
		0: 0,
		1: 0,
		2: unix.CSTOPB,
	}
)

type uart struct {
	path   string
	handle *os.File
}

func UARTProbe(path string) (control string, err error) {
	port, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	state := 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(port.Fd()), uintptr(syscall.TIOCMGET), uintptr(unsafe.Pointer(&state)), 0, 0, 0); errno != 0 {
		return "", errors.New("TICMGET errno:" + strconv.Itoa(int(errno)))
	}
	// state&syscall.TIOCM_CTS != 0
	port.Close()
	return
}

// in
// TIOCM_CD  = 0x40
// TIOCM_CTS = 0x20
// TIOCM_DSR = 0x100
// TIOCM_RI  = 0x80

// out
// TIOCM_DTR = 0x2
// TIOCM_RTS = 0x4

func UARTDial(path string, speed int, bit, parity, stop byte) (conn *uart, err error) {
	handle, err := os.OpenFile(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}

	if _, exists := speeds[speed]; !exists {
		speed = 9600
	}
	if _, exists := bits[bit]; !exists {
		bit = 8
	}
	if _, exists := parities[parity]; !exists {
		parity = 'N'
	}
	if _, exists := stops[stop]; !exists {
		stop = 1
	}
	fd := handle.Fd()
	// tios := unix.Termios{
	// 	Iflag:  unix.IGNPAR,
	// 	Cflag:  bits[bit] | parities[parity] | stops[stop],
	// 	Ispeed: speeds[speed],
	// 	Ospeed: speeds[speed],
	// }
	// tios.Cc[unix.VMIN] = 1
	// tios.Cc[unix.VTIME] = 0
	// if _, _, errno := unix.Syscall6(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCSETS), uintptr(unsafe.Pointer(&tios)), 0, 0, 0); errno != 0 {
	// 	return nil, errors.New("errno:" + strconv.Itoa(int(errno)))
	// }
	if err := unix.SetNonblock(int(fd), false); err != nil {
		return nil, err
	}

	return &uart{path: path, handle: handle}, nil
}
func (s *uart) Read(b []byte) (n int, err error) {
	// TODO deadline through termios vmin/vtime instead?
	return s.handle.Read(b)
}
func (s *uart) Write(b []byte) (n int, err error) {
	return s.handle.Write(b)
}
func (s *uart) Close() error {
	s.handle.Close()
	return nil
}
func (s *uart) Network() string {
	return "uart"
}
func (s *uart) String() string {
	return s.path
}
func (s *uart) LocalAddr() net.Addr {
	return s
}
func (s *uart) RemoteAddr() net.Addr {
	return s
}
func (s *uart) SetDeadline(t time.Time) error {
	return nil
}
func (s *uart) SetReadDeadline(t time.Time) error {
	return nil
}
func (s *uart) SetWriteDeadline(t time.Time) error {
	return nil
}

// handle := this.dvr.Fd()
// set.Bits[handle/64] |= (1 << (handle % 64))
// timeout := syscall.NsecToTimeval(int64(50 * time.Millisecond))
// if read, err := syscall.Select(int(handle)+1, &set, nil, nil, &timeout); err != nil || read <= 0 {
//     this.RUnlock()
//     if err != nil {
//         time.Sleep(50 * time.Millisecond)
//         return err, nil, 0, false, 0, 0, 0
//     } else {
//         return errors.New("packet failed: timeout"), nil, 0, false, 0, 0, 0
//     }
// }
// if read, err := this.dvr.Read(this.queue[:]); err != nil || read <= 0 {
//     this.RUnlock()
//     return err, nil, 0, false, 0, 0, 0
// } else {
//     this.qsize = read
//     this.qoffset = 0
// }
