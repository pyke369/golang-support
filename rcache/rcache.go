package rcache

import (
	"errors"
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
	nomatch = regexp.MustCompile(`^\x00{999}$`)
	mu      sync.RWMutex
	cache   = map[string]*entry{}
)

func GetErr(expr string) (matcher *regexp.Regexp, err error) {
	if expr = strings.TrimSpace(expr); len(expr) > 999 {
		return nomatch, errors.New("rcache: expression too long")
	}

	mu.RLock()
	if value, exists := cache[expr]; exists {
		mu.RUnlock()
		atomic.AddUint64(&value.hits, 1)
		return value.matcher, nil
	}
	mu.RUnlock()

	matcher, err = regexp.Compile(expr)
	if err == nil {
		mu.Lock()
		defer mu.Unlock()
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

		return matcher, nil
	}

	return nomatch, err
}

func Get(expr string) *regexp.Regexp {
	matcher, _ := GetErr(expr)

	return matcher
}
