package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

type UUID [16]byte

var (
	zero    = UUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	hex     = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	uhex    = map[byte]byte{'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15, 'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15}
	offsets = []int{0, 9, 14, 19, 24, 37}
	checker = []byte{
		'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
		'-',
		'x', 'x', 'x', 'x',
		'-',
		'v', 'x', 'x', 'x',
		'-',
		'f', 'x', 'x', 'x',
		'-',
		'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
	}
	base58  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	ubase58 = [256]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff, 0x11, 0x12, 0x13, 0x14, 0x15, 0xff,
		0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0xff, 0x2c, 0x2d, 0x2e,
		0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	done      = big.NewInt(0)
	base      = big.NewInt(58)
	over, _   = big.NewInt(0).SetString("ffffffffffffffffffffffffffffffff", 16)
	errFormat = errors.New("uuid: invalid format")
	errSize   = errors.New("uuid: invalid size")
	mu        sync.Mutex
	last      uint64
	lastts    uint64
)

func New(extra ...bool) (out UUID) {
	v7 := false
	if len(extra) != 0 {
		v7 = extra[0]
	}
	if v7 {
		mu.Lock()
		now := time.Now()
		sec := uint64(now.Unix())
		nsec := uint64(now.Nanosecond())
		msec := nsec / 1000000
		sub := nsec - (1000000 * msec)
		ts := ((1000*sec + msec) << 12) + ((sub * 4096) / 1000000)
		if last <= sec && ts <= lastts {
			ts = lastts + 1
		}
		last = sec
		lastts = ts
		mu.Unlock()

		binary.BigEndian.PutUint64(out[0:8], ((ts<<4)&0xffff_ffff_ffff_0000)|(ts&0x0ffff))
		out[6] = (out[6] & 0x0f) | 0x70
		_, _ = rand.Read(out[8:])

	} else {
		_, _ = rand.Read(out[:])
		out[6] = (out[6] & 0x0f) | 0x40
	}
	out[8] = (out[8] & 0x3f) | 0x80

	return
}

func Check(in string) bool {
	if len(in) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := in[i]
		switch checker[i] {
		case 'x':
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}

		case '-':
			if c != '-' {
				return false
			}

		case 'v':
			if c != '4' && c != '7' {
				return false
			}

		case 'f':
			if c != '8' && c != '9' && c != 'a' && c != 'A' && c != 'b' && c != 'B' {
				return false
			}
		}
	}

	return true
}

func Parse(in string) (out UUID, err error) {
	if !Check(in) {
		return out, errFormat
	}

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

	return
}

func FromBytes(in []byte) (out UUID, err error) {
	if len(in) != 16 {
		return out, errSize
	}
	copy(out[:], in)
	if !Check(out.String()) {
		return zero, errFormat
	}

	return
}

func (u UUID) String() string {
	out := make([]byte, 36)
	out[8], out[13], out[18], out[23] = '-', '-', '-', '-'

	for part := 0; part < len(offsets)-1; part++ {
		high := true
		for offset := offsets[part]; offset < offsets[part+1]-1; offset++ {
			index := (offset - part) / 2
			if high {
				out[offset] = hex[u[index]>>4]

			} else {
				out[offset] = hex[u[index]&0x0f]
			}
			high = !high
		}
	}

	return string(out)
}

func (u UUID) Encode() string {
	value, out := new(big.Int).SetBytes(u[:]), []byte{}
	for value.Cmp(done) > 0 {
		remainder := new(big.Int).Mod(value, base)
		out = append(out, base58[remainder.Int64()])
		value.Div(value, base)
	}
	for len(out) < 22 {
		out = append(out, '1')
	}

	return ustr.Reverse(string(out))
}

func Decode(in string) (out UUID, err error) {
	if len(in) != 22 {
		return zero, errFormat
	}

	value := big.NewInt(0)
	for _, c := range in {
		if c > 0xff || ubase58[c] == 0xff {
			return zero, errFormat
		}
		value.Mul(value, base)
		value.Add(value, big.NewInt(int64(ubase58[c])))
		if value.Cmp(over) > 0 {
			return zero, errFormat
		}
	}

	bytes := value.Bytes()
	if len(bytes) < 16 {
		bytes = append(make([]byte, 16-len(bytes)), bytes...)
	}
	copy(out[:], bytes)
	if !Check(out.String()) {
		return zero, errFormat
	}

	return
}
