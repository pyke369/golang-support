package uuid

import (
	"fmt"
	"math/rand"
	"os"
	"time"
)

var initialized bool

func init() {
	if !initialized {
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
		initialized = true
	}
}

func UUID() string {
	var entropy = make([]byte, 16)

	if !initialized {
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
		initialized = true
	}
	rand.Read(entropy)
	entropy[6] = (entropy[6] & 0x0f) | 0x40
	entropy[8] = (entropy[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", entropy[0:4], entropy[4:6], entropy[6:8], entropy[8:10], entropy[10:16])
}
