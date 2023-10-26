package gpio

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

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

type _GPIO_CHIPINFO struct {
	name  [32]byte
	label [32]byte
	lines uint32
}

// type _GPIO_LINEATTRIBUTE struct {
// 	id      uint32
// 	padding uint32
// 	values  uint64
// }
//
// type _GPIO_LINEINFO struct {
// 	name      [32]byte
// 	consumer  [32]byte
// 	offset    uint32
// 	num_attrs uint32
// 	flags     uint64
// 	attrs     [10]_GPIO_LINEATTRIBUTE
// 	padding   [4]uint32
// }

type GPIO struct {
	handle uintptr
	name   string
	label  string
	lines  int
}

func NewGPIO(index ...int) (gpio *GPIO, err error) {
	chip := 0
	if len(index) > 0 {
		chip = index[0]
	}
	handle, err := os.Open(fmt.Sprintf("/dev/gpiochip%d", chip))
	if err != nil {
		return nil, err
	}
	info := _GPIO_CHIPINFO{}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, handle.Fd(), _GPIO_GET_CHIPINFO, uintptr(unsafe.Pointer(&info))); errno != 0 {
		return nil, err
	}
	gpio = &GPIO{
		handle: handle.Fd(),
		name:   string(info.name[:bytes.Index(info.name[:], []byte{0})]),
		label:  string(info.label[:bytes.Index(info.label[:], []byte{0})]),
		lines:  int(info.lines),
	}

	// TODO
	// for line := 0; line < int(cinfo.lines); line++ {
	//     linfo.offset = uint32(line)
	//     if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, handle.Fd(), GPIO_GET_LINEINFO, uintptr(unsafe.Pointer(&linfo))); errno == 0 {
	//         fmt.Printf("%2d  %-16.16s  %-8.8s  %d\n", line, linfo.name, linfo.consumer, linfo.num_attrs)
	//     }
	// }

	return
}

func (g *GPIO) Name() string {
	return g.name
}
func (g *GPIO) Label() string {
	return g.label
}
func (g *GPIO) Lines() int {
	return g.lines
}
