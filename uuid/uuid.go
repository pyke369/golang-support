package uuid

import (
	"crypto/rand"
	"strings"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

type UUID [16]byte

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
	return rcache.Get(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(strings.ToLower(in))
}

func (u UUID) String() string {
	return ustr.Hex(u[0:4]) + "-" + ustr.Hex(u[4:6]) + "-" + ustr.Hex(u[6:8]) + "-" + ustr.Hex(u[8:10]) + "-" + ustr.Hex(u[10:16])
}
