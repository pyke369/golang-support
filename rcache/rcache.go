package rcache

import (
	"container/list"
	"errors"
	"regexp"
	"strings"
	"sync"
)

type entry struct {
	expr    string
	matcher *regexp.Regexp
}

var (
	nomatch = regexp.MustCompile(`^\x00{256}$`)
	mu      sync.RWMutex
	cache   = map[string]*list.Element{}
	lru     = list.New()
)

func GetErr(expr string) (matcher *regexp.Regexp, err error) {
	if expr = strings.TrimSpace(expr); len(expr) > 256 {
		return nil, errors.New("rcache: expression too long")
	}

	mu.Lock()
	if value, exists := cache[expr]; exists {
		lru.MoveToFront(value)
		mu.Unlock()
		return value.Value.(*entry).matcher, nil
	}
	mu.Unlock()

	matcher, err = regexp.Compile(expr)
	if err == nil {
		mu.Lock()
		if _, exists := cache[expr]; !exists {
			if len(cache) >= 8<<10 {
				if value := lru.Back(); value != nil {
					if value := lru.Remove(value); value != nil {
						delete(cache, value.(*entry).expr)
					}
				}
			}
			cache[expr] = lru.PushFront(&entry{expr: expr, matcher: matcher})
		}
		mu.Unlock()
		return matcher, nil
	}

	return nil, err
}

func Get(expr string) *regexp.Regexp {
	matcher, err := GetErr(expr)
	if err != nil {
		return nomatch
	}

	return matcher
}
