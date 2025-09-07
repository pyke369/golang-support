package uuid

import (
	"crypto/rand"
	"unsafe"
)

type UUID [16]byte

var (
	parts = []int{0, 9, 14, 19, 24, 37}
	hex   = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	uhex  = map[byte]byte{'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15, 'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15}
)

func New() (out UUID) {
	rand.Read(out[:])
	out[6] = (out[6] & 0x0f) | 0x40
	out[8] = (out[8] & 0x3f) | 0x80
	return
}

func From(in []byte) (out UUID) {
	if len(in) >= 16 {
		copy(out[:], in[:16])
		out[6] = (out[6] & 0x0f) | 0x40
		out[8] = (out[8] & 0x3f) | 0x80
	}
	return
}

func Check(in string) bool {
	if len(in) != 36 {
		return false
	}

	for part := 0; part < len(parts)-1; part++ {
		if part > 0 && in[parts[part]-1] != '-' {
			return false
		}
		for offset := parts[part]; offset < parts[part+1]-1; offset++ {
			char := in[offset]
			if (char < '0' || char > 'f') || (char > '9' && char < 'A') || (char > 'F' && char < 'a') {
				return false
			}
		}
	}

	return true
}

func Unmarshal(in string) (out UUID) {
	if Check(in) {
		out[0] = (uhex[in[0]] << 4) | uhex[in[1]]
		out[1] = (uhex[in[2]] << 4) | uhex[in[3]]
		out[2] = (uhex[in[4]] << 4) | uhex[in[5]]
		out[3] = (uhex[in[6]] << 4) | uhex[in[7]]

		out[4] = (uhex[in[9]] << 4) | uhex[in[10]]
		out[5] = (uhex[in[11]] << 4) | uhex[in[12]]

		out[6] = (uhex[in[14]] << 4) | uhex[in[15]]
		out[7] = (uhex[in[16]] << 4) | uhex[in[17]]

		out[8] = (uhex[in[19]] << 4) | uhex[in[20]]
		out[9] = (uhex[in[21]] << 4) | uhex[in[22]]

		out[10] = (uhex[in[24]] << 4) | uhex[in[25]]
		out[11] = (uhex[in[26]] << 4) | uhex[in[27]]
		out[12] = (uhex[in[28]] << 4) | uhex[in[29]]
		out[13] = (uhex[in[30]] << 4) | uhex[in[31]]
		out[14] = (uhex[in[32]] << 4) | uhex[in[33]]
		out[15] = (uhex[in[34]] << 4) | uhex[in[35]]
	}
	return
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
