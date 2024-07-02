package uuid

import (
	"crypto/rand"
	"strings"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ufmt"
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
	return ufmt.Hex(u[0:4]) + "-" + ufmt.Hex(u[4:6]) + "-" + ufmt.Hex(u[6:8]) + "-" + ufmt.Hex(u[8:10]) + "-" + ufmt.Hex(u[10:16])
}
