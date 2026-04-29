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
	if expression = strings.TrimSpace(expression); len(expression) > 256 {
		return nomatch
	}
	mu.Lock()
	defer mu.Unlock()
	if cache[expression] != nil {
		return cache[expression]
	}
	if regex, err := regexp.Compile(expression); err == nil {
		if len(cache) < 4<<10 {
			cache[expression] = regex
		}
		return regex
	}

	return nomatch
}
