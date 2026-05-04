package rcache

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type entry struct {
	expr    string
	matcher *regexp.Regexp
	hits    uint64
}

var (
	nomatch = regexp.MustCompile(`^\x00{128}$`)
	mu      sync.RWMutex
	cache   = map[string]*entry{}
)

func Get(expr string) *regexp.Regexp {
	if expr = strings.TrimSpace(expr); len(expr) > 128 {
		return nomatch
	}

	mu.RLock()
	if value, exists := cache[expr]; exists {
		mu.RUnlock()
		atomic.AddUint64(&value.hits, 1)
		return value.matcher
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if matcher, err := regexp.Compile(expr); err == nil {
		if len(cache) >= 4<<10 {
			entries := []*entry{}
			for _, entry := range cache {
				entries = append(entries, entry)
			}
			sort.SliceStable(entries, func(i, j int) bool {
				return entries[i].hits < entries[j].hits
			})
			end := len(entries) / 4
			for index, entry := range entries {
				delete(cache, entry.expr)
				if index >= end {
					break
				}
			}
		}
		if len(cache) < 4<<10 {
			cache[expr] = &entry{expr: expr, matcher: matcher, hits: 1}
		}

		return matcher
	}

	return nomatch
}
