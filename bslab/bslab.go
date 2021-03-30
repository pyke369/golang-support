package bslab

import "sync/atomic"

type slab struct {
	queue                 chan []byte
	get, put, alloc, lost int64
}

var (
	slabs = map[int]*slab{}
)

func init() {
	slabs[0] = &slab{}
	for size := uint(8); size <= 26; size++ {
		slabs[1<<size] = &slab{queue: make(chan []byte, 1024)}
	}
}

func Stats() (info map[int][5]int64) {
	info = map[int][5]int64{}
	for size, slab := range slabs {
		info[size] = [5]int64{slab.get, slab.put, slab.alloc, slab.lost, int64(len(slab.queue))}
	}
	return info
}

func Get(size int, item []byte) []byte {
	if size <= 0 {
		return nil
	}
	if item != nil {
		if cap(item) >= size {
			return item[:0]
		}
		Put(item)
	}
	bits, power := uint(0), uint(0)
	if size&(size-1) == 0 {
		power = 1
	}
	for size != 0 {
		size >>= 1
		bits++
	}
	size = 1 << (bits - power)
	if slab, ok := slabs[size]; ok {
		atomic.AddInt64(&(slab.get), 1)
		select {
		case item := <-slab.queue:
			return item[:0]
		default:
			atomic.AddInt64(&(slab.alloc), 1)
			return make([]byte, 0, size)
		}
	}
	atomic.AddInt64(&(slabs[0].get), 1)
	atomic.AddInt64(&(slabs[0].alloc), int64(size))
	return make([]byte, 0, size)
}

func Put(item []byte) {
	if item == nil || cap(item) <= 0 {
		return
	}
	size, bits := cap(item), uint(0)
	for size != 0 {
		size >>= 1
		bits++
	}
	size = 1 << (bits - 1)
	if size > 0 && float64(cap(item))/float64(size) <= 1.2 {
		if slab, ok := slabs[size]; ok {
			atomic.AddInt64(&(slab.put), 1)
			select {
			case slab.queue <- item:
			default:
				atomic.AddInt64(&(slab.lost), 1)
			}
		} else {
			atomic.AddInt64(&(slabs[0].put), 1)
			atomic.AddInt64(&(slabs[0].lost), int64(cap(item)))
		}
	} else {
		atomic.AddInt64(&(slabs[0].put), 1)
		atomic.AddInt64(&(slabs[0].lost), int64(cap(item)))
	}
}
