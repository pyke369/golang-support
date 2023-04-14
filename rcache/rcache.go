package rcache

import (
	"regexp"
	"sync"
	"sync/atomic"
)

var (
	cache map[string]*regexp.Regexp = map[string]*regexp.Regexp{}
	hit   int64
	miss  int64
	lock  sync.RWMutex
)

func Get(expression string) *regexp.Regexp {
	lock.RLock()
	if cache[expression] != nil {
		atomic.AddInt64(&hit, 1)
		defer lock.RUnlock()
		return cache[expression]
	}
	atomic.AddInt64(&miss, 1)
	lock.RUnlock()
	if regex, err := regexp.Compile(expression); err == nil {
		lock.Lock()
		defer lock.Unlock()
		cache[expression] = regex
		return cache[expression]
	}
	return nil
}

func Stats() (int, int64, int64) {
	lock.RLock()
	defer lock.RUnlock()
	return len(cache), atomic.LoadInt64(&hit), atomic.LoadInt64(&miss)
}
