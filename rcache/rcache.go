package rcache

import (
	"crypto/md5"
	"regexp"
	"sync"
	"sync/atomic"
)

var (
	cache map[[16]byte]*regexp.Regexp = map[[16]byte]*regexp.Regexp{}
	hit   int64
	miss  int64
	lock  sync.RWMutex
)

func Get(expression string) *regexp.Regexp {
	key := md5.Sum([]byte(expression))
	lock.RLock()
	if cache[key] != nil {
		atomic.AddInt64(&hit, 1)
		defer lock.RUnlock()
		return cache[key]
	}
	atomic.AddInt64(&miss, 1)
	lock.RUnlock()
	if regex, err := regexp.Compile(expression); err == nil {
		lock.Lock()
		defer lock.Unlock()
		cache[key] = regex
		return cache[key]
	}
	return nil
}

func Stats() (int, int64, int64) {
	lock.RLock()
	defer lock.RUnlock()
	return len(cache), atomic.LoadInt64(&hit), atomic.LoadInt64(&miss)
}
