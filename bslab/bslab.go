package bslab

import (
	"sort"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/pyke369/golang-support/ustr"
)

type slab struct {
	max   uint32
	queue chan []byte
	get   uint32
	put   uint32
	alloc uint32
	lost  uint32
}

type Arena struct {
	name  string
	slabs map[int]*slab
}

type Info struct {
	Name   string
	Values map[int][6]uint32
}

var base Arena

func init() {
	base = New(map[string]any{"name": "base"})
}

func New(extra ...map[string]any) Arena {
	a := Arena{slabs: map[int]*slab{}}
	a.slabs[0] = &slab{}
	for size := uint(8); size <= 26; size++ {
		a.slabs[1<<size] = &slab{queue: make(chan []byte, 64<<10)}
	}
	if len(extra) > 0 {
		if value, ok := extra[0]["name"].(string); ok {
			a.name = value
		}
		if value1, ok := extra[0]["max"].(map[int]int); ok {
			for size := range a.slabs {
				if value2, ok := value1[size]; ok && value2 > 0 {
					a.slabs[size].max = uint32(value2)
				}
			}
		}
	}
	return a
}

func (a Arena) Get(size int, extra ...[]byte) (out []byte) {
	var item []byte

	if len(extra) != 0 {
		item = extra[0]
	}
	if size <= 0 {
		return nil
	}
	if size < (1 << 8) {
		size = (1 << 8)
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
	if slab, exists := a.slabs[size]; exists {
		atomic.AddUint32(&(slab.get), 1)
		if slab.max == 0 || atomic.LoadUint32(&(slab.alloc)) < slab.max {
			select {
			case item := <-slab.queue:
				out = item[:0]

			default:
				atomic.AddUint32(&(slab.alloc), 1)
				out = make([]byte, 0, size)
			}
		} else {
			item := <-slab.queue
			out = item[:0]
		}
	}
	if out == nil {
		atomic.AddUint32(&(a.slabs[0].get), 1)
		atomic.AddUint32(&(a.slabs[0].alloc), uint32(size))
		out = make([]byte, 0, size)
	}
	return
}
func Get(size int, extra ...[]byte) (out []byte) {
	return base.Get(size, extra...)
}

func (a Arena) Put(in []byte) {
	if in == nil || cap(in) <= 0 {
		return
	}
	size, bits := cap(in), uint(0)
	for size != 0 {
		size >>= 1
		bits++
	}
	size = 1 << (bits - 1)
	if size > 0 && float64(cap(in))/float64(size) <= 1.25 {
		if slab, exists := a.slabs[size]; exists {
			atomic.AddUint32(&(slab.put), 1)
			select {
			case slab.queue <- in:

			default:
				atomic.AddUint32(&(slab.lost), 1)
			}
		} else {
			atomic.AddUint32(&(a.slabs[0].put), 1)
			atomic.AddUint32(&(a.slabs[0].lost), uint32(cap(in)))
		}
	} else {
		atomic.AddUint32(&(a.slabs[0].put), 1)
		atomic.AddUint32(&(a.slabs[0].lost), uint32(cap(in)))
	}
}
func Put(in []byte) {
	base.Put(in)
}

func hcount(in uint32) string {
	if in <= 0 {
		return "."
	}
	return strconv.Itoa(int(in))
}
func hsize(in uint32) string {
	if in <= 0 {
		return "."
	}
	if in < (1 << 10) {
		return strconv.Itoa(int(in)) + " B"
	}
	if in < (1 << 20) {
		return strconv.Itoa(int(in/(1<<10))) + " kB"
	}
	if in < (1 << 30) {
		return strconv.Itoa(int(in/(1<<20))) + " MB"
	}
	return strconv.Itoa(int(in/(1<<30))) + " GB"
}
func (a Arena) Stat() Info {
	info := Info{
		Name:   a.name,
		Values: map[int][6]uint32{},
	}
	for size, slab := range a.slabs {
		info.Values[size] = [6]uint32{
			slab.max,
			atomic.LoadUint32(&(slab.alloc)),
			uint32(len(slab.queue)),
			atomic.LoadUint32(&(slab.lost)),
			atomic.LoadUint32(&(slab.get)),
			atomic.LoadUint32(&(slab.put)),
		}
	}
	return info
}
func Stat() Info {
	return base.Stat()
}
func (i Info) String() string {
	sizes := make([]int, 0, len(i.Values))
	for size := range i.Values {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)

	out, alloc, lost := make([]byte, 0, (len(sizes)+6)*80), uint32(0), uint32(0)
	out = append(out, "------------------------------------------------------------------------------\n"...)
	out = append(out, "    size      max    alloc   active    avail       lost        get        put\n"...)
	out = append(out, "------------------------------------------------------------------------------\n"...)
	for _, size := range sizes {
		if i.Values[size][1] == 0 {
			continue
		}
		alloc += i.Values[size][1] * uint32(size)
		lost += i.Values[size][3]
		out = append(out, ustr.String(hsize(uint32(size)), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][0]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][1]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][1]-i.Values[size][2]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][2]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hsize(i.Values[size][3]), 10)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][4]), 10)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][5]), 10)...)
		out = append(out, '\n')
	}
	out = append(out, "------------------------------------------------------------------------------\n"...)
	out = append(out, ustr.String(hsize(alloc), 26)...)
	out = append(out, ustr.String(hsize(lost), 29)...)
	out = append(out, '\n')
	out = append(out, "------------------------------------------------------------------------------\n"...)
	return unsafe.String(unsafe.SliceData(out), len(out))
}
