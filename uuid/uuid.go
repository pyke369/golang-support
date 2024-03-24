package uuid

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/pyke369/golang-support/rcache"
)

type UUID [16]byte

func New() (uuid UUID) {
	rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return
}

func Check(in string) bool {
	return rcache.Get(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(strings.ToLower(in))
}

func (u UUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
