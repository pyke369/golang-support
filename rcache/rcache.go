package rcache

import (
	"crypto/md5"
	"regexp"
	"runtime"
	"sync"
)

var (
	cores int
	cache map[[16]byte]*regexp.Regexp = map[[16]byte]*regexp.Regexp{}
	lock  sync.RWMutex
)

func Get(expression string) *regexp.Regexp {
	if cores == 0 {
		cores = runtime.NumCPU()
	}
	key := md5.Sum([]byte(expression))
	if cores > 1 {
		lock.RLock()
	}
	if cache[key] != nil {
		if cores > 1 {
			defer lock.RUnlock()
		}
		return cache[key].Copy()
	}
	if cores > 1 {
		lock.RUnlock()
	}
	if regex, err := regexp.Compile(expression); err == nil {
		if cores > 1 {
			lock.Lock()
			defer lock.Unlock()
		}
		cache[key] = regex
		return cache[key].Copy()
	}
	return nil
}
