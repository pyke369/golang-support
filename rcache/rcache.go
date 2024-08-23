package rcache

import (
	"regexp"
	"sync"
	"sync/atomic"
)

var (
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp = map[string]*regexp.Regexp{}
	hit   int64
	miss  int64
)

func Get(expression string) *regexp.Regexp {
	mu.RLock()
	if cache[expression] != nil {
		atomic.AddInt64(&hit, 1)
		defer mu.RUnlock()
		return cache[expression]
	}
	atomic.AddInt64(&miss, 1)
	mu.RUnlock()
	if regex, err := regexp.Compile(expression); err == nil {
		mu.Lock()
		defer mu.Unlock()
		cache[expression] = regex
		return cache[expression]
	}
	return nil
}

func Stats() (size int, hit, miss int64) {
	mu.RLock()
	defer mu.RUnlock()
	return len(cache), atomic.LoadInt64(&hit), atomic.LoadInt64(&miss)
}
