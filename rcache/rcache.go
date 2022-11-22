package rcache

import (
	"hash/crc32"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"unsafe"
)

var (
	cache map[uint32]*regexp.Regexp = map[uint32]*regexp.Regexp{}
	hit   int64
	miss  int64
	lock  sync.RWMutex
)

func Get(expression string) *regexp.Regexp {
	var slice []byte

	hslice := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	hstring := (*reflect.StringHeader)(unsafe.Pointer(&expression))
	hslice.Data = hstring.Data
	hslice.Cap = hstring.Len
	hslice.Len = hstring.Len
	key := crc32.ChecksumIEEE(slice)
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
