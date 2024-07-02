package ufmt

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return errors.New(msg + ": " + err.Error())
}

func Int(in int, extra ...int) (out string) {
	out = strconv.Itoa(in)
	if in >= 0 && len(extra) != 0 {
		size := max(0, extra[0])
		if len(out) < size {
			out = strings.Repeat("0", size-len(out)) + out
		}
	}
	return
}

func String(in string, extra ...int) (out string) {
	out = in
	size, left := 0, false
	if len(extra) != 0 {
		if extra[0] < 0 {
			left = true
			size, left = -extra[0], true
		} else {
			size = extra[0]
		}
	}
	if len(out) < size {
		if left {
			out += strings.Repeat(" ", size-len(out))
		} else {
			out = strings.Repeat(" ", size-len(out)) + out
		}
	}
	return
}

func Hex(in []byte, extra ...string) (out string) {
	if len(in) != 0 {
		separator, hex := []byte{}, "0123456789abcdef"
		if len(extra) != 0 {
			separator = []byte(extra[0])
		}
		length := len(in)
		buffer := make([]byte, 0, length+(len(separator))*(length-1))
		for index, value := range in {
			buffer = append(buffer, hex[value>>4])
			buffer = append(buffer, hex[value&0x0f])
			if index < length-1 {
				buffer = append(buffer, separator...)
			}
		}
		out = unsafe.String(unsafe.SliceData(buffer), len(buffer))
	}
	return
}
