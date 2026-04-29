package bslab

import (
	"sort"
	"strconv"
	"sync/atomic"

	"github.com/pyke369/golang-support/ustr"
)

type slab struct {
	max   uint64
	queue chan []byte
	get   uint64
	put   uint64
	alloc uint64
	lost  uint64
}

type Arena struct {
	name  string
	slabs map[int]*slab
}

type Info struct {
	Name   string
	Values map[int][6]uint64
}

var Default *Arena

func init() {
	Default = New(map[string]any{"name": "default"})
}

func New(extra ...map[string]any) *Arena {
	a := &Arena{slabs: map[int]*slab{}}
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
					a.slabs[size].max = uint64(value2)
				}
			}
		}
	}
	return a
}

func (a *Arena) Get(size int, extra ...[]byte) (out []byte) {
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
			out = item[:0]
		}
		if out == nil {
			Put(item)
		}
	}
	if out == nil {
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
			atomic.AddUint64(&(slab.get), 1)
			if slab.max == 0 || atomic.LoadUint64(&(slab.alloc)) < slab.max {
				select {
				case item := <-slab.queue:
					out = item[:0]

				default:
					atomic.AddUint64(&(slab.alloc), 1)
					out = make([]byte, 0, size)
				}

			} else {
				select {
				case item := <-slab.queue:
					out = item[:0]

				default:
				}
			}
		}
		if out == nil {
			atomic.AddUint64(&(a.slabs[0].get), 1)
			atomic.AddUint64(&(a.slabs[0].alloc), uint64(size))
			out = make([]byte, 0, size)
		}
	}

	return
}

func Get(size int, extra ...[]byte) (out []byte) {
	return Default.Get(size, extra...)
}

func (a *Arena) Put(in []byte, zeroize ...bool) {
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
			if len(zeroize) == 0 || zeroize[0] {
				in = in[:cap(in)]
				for index := 0; index < cap(in); index++ {
					in[index] = 0
				}
			}
			atomic.AddUint64(&(slab.put), 1)
			select {
			case slab.queue <- in:

			default:
				atomic.AddUint64(&(slab.lost), 1)
			}

		} else {
			atomic.AddUint64(&(a.slabs[0].put), 1)
			atomic.AddUint64(&(a.slabs[0].lost), uint64(cap(in)))
		}

	} else {
		atomic.AddUint64(&(a.slabs[0].put), 1)
		atomic.AddUint64(&(a.slabs[0].lost), uint64(cap(in)))
	}
}

func Put(in []byte) {
	Default.Put(in)
}

func hcount(in uint64) string {
	if in <= 0 {
		return "."
	}

	return strconv.FormatUint(in, 10)
}

func hsize(in uint64) string {
	if in <= 0 {
		return "."
	}

	if in < (1 << 10) {
		return strconv.FormatUint(in, 10) + " B"
	}
	if in < (1 << 20) {
		return strconv.FormatUint(in/(1<<10), 10) + " kB"
	}
	if in < (1 << 30) {
		return strconv.FormatUint(in/(1<<20), 10) + " MB"
	}

	return strconv.FormatUint(in/(1<<30), 10) + " GB"
}

func (a *Arena) Stat() *Info {
	info := &Info{
		Name:   a.name,
		Values: map[int][6]uint64{},
	}
	for size, slab := range a.slabs {
		info.Values[size] = [6]uint64{
			uint64(slab.max),
			atomic.LoadUint64(&(slab.alloc)),
			uint64(len(slab.queue)),
			atomic.LoadUint64(&(slab.lost)),
			atomic.LoadUint64(&(slab.get)),
			atomic.LoadUint64(&(slab.put)),
		}
	}
	return info
}

func Stat() *Info {
	return Default.Stat()
}

func (i *Info) String() string {
	sizes := make([]int, 0, len(i.Values))
	for size := range i.Values {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)

	out, alloc, lost := make([]byte, 0, (len(sizes)+6)*80), uint64(0), uint64(0)
	out = append(out, "------------------------------------------------------------------------------\n"...)
	out = append(out, "    size      max    alloc   active    avail       lost        get        put\n"...)
	out = append(out, "------------------------------------------------------------------------------\n"...)
	for _, size := range sizes {
		if i.Values[size][1] == 0 {
			continue
		}
		active := uint64(0)
		if i.Values[size][1] > i.Values[size][2] {
			active = i.Values[size][1] - i.Values[size][2]
		}
		out = append(out, ustr.String(hsize(uint64(size)), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][0]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][1]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(active), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][2]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hsize(i.Values[size][3]), 10)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][4]), 10)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(i.Values[size][5]), 10)...)
		out = append(out, '\n')

		alloc += i.Values[size][1] * uint64(size)
		lost += i.Values[size][3]
	}
	out = append(out, "------------------------------------------------------------------------------\n"...)
	out = append(out, ustr.String(hsize(alloc), 26)...)
	out = append(out, ustr.String(hsize(lost), 29)...)
	out = append(out, '\n')
	out = append(out, "------------------------------------------------------------------------------\n"...)
	return string(out)
}
