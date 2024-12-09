package gpio

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

// GPIO API
const (
	_GPIO_GET_CHIPINFO         = 0x8044b401
	_GPIO_GET_LINEINFO         = 0xc100b405
	_GPIO_GET_LINE             = 0xc250b407
	_GPIO_LINE_SET_CONFIG      = 0xc110b40d
	_GPIO_LINE_GET_VALUES      = 0xc010b40e
	_GPIO_LINE_SET_VALUES      = 0xc010b40f
	_GPIO_GET_LINEINFO_WATCH   = 0xc100b406
	_GPIO_GET_LINEINFO_UNWATCH = 0xc004b40c
)

var (
	_GPIO_LINE_FLAGS = map[int]string{
		1 << 0:  "used",
		1 << 1:  "active-low",
		1 << 2:  "input",
		1 << 3:  "output",
		1 << 4:  "edge-rising",
		1 << 5:  "edge-falling",
		1 << 6:  "open-drain",
		1 << 7:  "open-source",
		1 << 8:  "bias-pull-up",
		1 << 9:  "bias-pull-down",
		1 << 10: "bias-disabled",
		1 << 11: "event-clock-realtime",
		1 << 12: "event-clock-hte",
	}
)

type _GPIO_CHIPINFO struct {
	name  [32]byte
	label [32]byte
	lines uint32
}
type _GPIO_LINEATTRIBUTE struct {
	id      uint32
	padding uint32
	value   uint64
}
type _GPIO_LINEINFO struct {
	name      [32]byte
	consumer  [32]byte
	offset    uint32
	num_attrs uint32
	flags     uint64
	attrs     [10]_GPIO_LINEATTRIBUTE
	padding   [4]uint32
}

type GPIO struct {
	handle uintptr
	name   string
	label  string
	lines  int
}
type GPIO_LINE struct {
	Name     string
	Consumer string
	Flags    []string
	Debounce uint32
}

func NumGPIO() int {
	if entries, err := filepath.Glob("/dev/gpiochip*"); err == nil {
		return len(entries)
	}
	return 0
}

func NewGPIO(index ...int) (gpio *GPIO, err error) {
	chip := 0
	if len(index) > 0 {
		chip = index[0]
	}
	handle, err := os.Open("/dev/gpiochip" + strconv.Itoa(chip))
	if err != nil {
		return nil, err
	}
	info := _GPIO_CHIPINFO{}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, handle.Fd(), _GPIO_GET_CHIPINFO, uintptr(unsafe.Pointer(&info))); errno != 0 {
		return nil, errors.New("errno: " + strconv.Itoa(int(errno)))
	}
	gpio = &GPIO{
		handle: handle.Fd(),
		name:   string(info.name[:bytes.Index(info.name[:], []byte{0})]),
		label:  string(info.label[:bytes.Index(info.label[:], []byte{0})]),
		lines:  int(info.lines),
	}
	return
}
func (g *GPIO) Name() string {
	return g.name
}
func (g *GPIO) Label() string {
	return g.label
}

func (g *GPIO) Lines() (lines []*GPIO_LINE) {
	lines = []*GPIO_LINE{}
	for index := 0; index < g.lines; index++ {
		info := _GPIO_LINEINFO{offset: uint32(index)}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, g.handle, _GPIO_GET_LINEINFO, uintptr(unsafe.Pointer(&info))); errno == 0 {
			flags, debounce := []string{}, uint32(0)
			for bit := 0; bit < 32; bit++ {
				if info.flags&(1<<bit) != 0 {
					if value := _GPIO_LINE_FLAGS[1<<bit]; value != "" {
						flags = append(flags, value)
					}
				}
			}
			for attribute := 0; attribute < int(info.num_attrs); attribute++ {
				switch info.attrs[attribute].id {
				case 1:
					flags = []string{}
					for bit := 0; bit < 32; bit++ {
						if info.attrs[attribute].value&(1<<bit) != 0 {
							if value := _GPIO_LINE_FLAGS[1<<bit]; value != "" {
								flags = append(flags, value)
							}
						}
					}

				case 3:
					debounce = uint32(info.attrs[attribute].value >> 32)
				}
			}
			lines = append(lines, &GPIO_LINE{
				Name:     string(info.name[:bytes.Index(info.name[:], []byte{0})]),
				Consumer: string(info.consumer[:bytes.Index(info.consumer[:], []byte{0})]),
				Flags:    flags,
				Debounce: debounce,
			})
		}
	}
	return
}

// PWM API

// I2C API

// SPI API

// UART API
