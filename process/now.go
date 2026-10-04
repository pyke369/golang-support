package process

import (
	"sync/atomic"
	"time"
)

var now atomic.Pointer[time.Time]

func init() {
	current := time.Now()
	now.Store(&current)
	go func() {
		for range time.Tick(10 * time.Millisecond) {
			current := time.Now()
			now.Store(&current)
		}
	}()
}

func Now() time.Time {
	current := now.Load()

	return *current
}
