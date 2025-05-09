package rcache

import (
	"regexp"
	"strings"
	"sync"
)

var (
	nomatch = regexp.MustCompile(`^\x00{256}$`)
	mu      sync.RWMutex
	cache   map[string]*regexp.Regexp = map[string]*regexp.Regexp{}
)

func Get(expression string) *regexp.Regexp {
	expression = strings.TrimSpace(expression)
	mu.RLock()
	if cache[expression] != nil {
		defer mu.RUnlock()
		return cache[expression]
	}
	mu.RUnlock()
	if regex, err := regexp.Compile(expression); err == nil {
		mu.Lock()
		defer mu.Unlock()
		cache[expression] = regex
		return cache[expression]
	}
	return nomatch
}
