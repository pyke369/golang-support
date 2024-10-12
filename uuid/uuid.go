package uuid

import (
	"crypto/rand"
	"unsafe"
)

type UUID [16]byte

var (
	parts = []int{0, 9, 14, 19, 24, 37}
	hex   = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
)

func New() (uuid UUID) {
	rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return
}

func From(source []byte) (uuid UUID) {
	if len(source) >= 16 {
		copy(uuid[:], source[:16])
		uuid[6] = (uuid[6] & 0x0f) | 0x40
		uuid[8] = (uuid[8] & 0x3f) | 0x80
	}
	return
}

func Check(in string) bool {
	if len(in) != 36 || in[8] != '-' || in[13] != '-' || in[18] != '-' || in[23] != '-' {
		return false
	}

	for part := 0; part < len(parts)-1; part++ {
		for offset := parts[part]; offset < parts[part+1]-1; offset++ {
			char := in[offset]
			if (char < '0' || char > 'f') || (char > '9' && char < 'A') || (char > 'F' && char < 'a') {
				return false
			}
		}
	}

	return true
}

func (u UUID) String() string {
	out := make([]byte, 36)
	out[8], out[13], out[18], out[23] = '-', '-', '-', '-'

	for part := 0; part < len(parts)-1; part++ {
		high := true
		for offset := parts[part]; offset < parts[part+1]-1; offset++ {
			index := (offset - part) / 2
			if high {
				out[offset] = hex[u[index]>>4]
			} else {
				out[offset] = hex[u[index]&0x0f]
			}
			high = !high
		}
	}

	return unsafe.String(unsafe.SliceData(out), len(out))
}
