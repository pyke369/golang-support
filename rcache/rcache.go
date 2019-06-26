package rcache

import (
	"crypto/md5"
	"regexp"
	"sync"
)

var (
	cache map[[16]byte]*regexp.Regexp = map[[16]byte]*regexp.Regexp{}
	lock  sync.RWMutex
)

func Get(expression string) *regexp.Regexp {
	key := md5.Sum([]byte(expression))
	lock.RLock()
	if cache[key] != nil {
		defer lock.RUnlock()
		return cache[key].Copy()
	}
	lock.RUnlock()
	if regex, err := regexp.Compile(expression); err == nil {
		lock.Lock()
		defer lock.Unlock()
		cache[key] = regex
		return cache[key].Copy()
	}
	return nil
}
