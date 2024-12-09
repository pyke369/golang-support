package bslab

import (
	"encoding/binary"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/pyke369/golang-support/ustr"
)

type STATS map[int][5]uint32

type slab struct {
	queue                 chan []byte
	get, put, alloc, lost uint32
}

var (
	slabs  = map[int]*slab{}
	tracer io.Writer
	low    = -1
	high   = -1
)

func init() {
	slabs[0] = &slab{}
	for size := uint(8); size <= 26; size++ {
		slabs[1<<size] = &slab{queue: make(chan []byte, 64<<10)}
	}
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

func Trace(in io.Writer, boundaries ...int) {
	tracer = in
	if len(boundaries) > 0 {
		low = max(-1, boundaries[0])
		if len(boundaries) > 1 {
			high = max(-1, boundaries[1])
		}
	}
}

func Stats() (out STATS) {
	out = STATS{}
	for size, slab := range slabs {
		out[size] = [5]uint32{
			atomic.LoadUint32(&(slab.get)),
			atomic.LoadUint32(&(slab.put)),
			atomic.LoadUint32(&(slab.alloc)),
			atomic.LoadUint32(&(slab.lost)),
			uint32(len(slab.queue)),
		}
	}
	return
}

func (s STATS) String() string {
	sizes := make([]int, 0, len(s))
	for size := range s {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)
	out := make([]byte, 0, (len(sizes)+4)*64)
	out = append(out, "------------------------------------------------------\n"...)
	out = append(out, "    size      get      put    alloc     lost    queue\n"...)
	out = append(out, "------------------------------------------------------\n"...)
	for _, size := range sizes {
		out = append(out, ustr.String(hsize(uint32(size)), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(s[size][0]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(s[size][1]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(s[size][2]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hsize(s[size][3]), 8)...)
		out = append(out, ' ')
		out = append(out, ustr.String(hcount(s[size][4]), 8)...)
		out = append(out, '\n')
	}
	out = append(out, "------------------------------------------------------\n"...)
	return unsafe.String(unsafe.SliceData(out), len(out))
}

func Get(size int, extra ...[]byte) (out []byte) {
	var item []byte

	isize := size
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
	if slab, exists := slabs[size]; exists {
		atomic.AddUint32(&(slab.get), 1)
		select {
		case item := <-slab.queue:
			out = item[:0]

		default:
			atomic.AddUint32(&(slab.alloc), 1)
			out = make([]byte, 0, size)
		}
	}
	if out == nil {
		atomic.AddUint32(&(slabs[0].get), 1)
		atomic.AddUint32(&(slabs[0].alloc), uint32(size))
		out = make([]byte, 0, size)
	}
	if tracer != nil && (low == -1 || size >= low) && (high == -1 || size <= high) {
		if _, file, line, ok := runtime.Caller(1); ok {
			address := make([]byte, 8)
			binary.BigEndian.PutUint64(address, *(*uint64)(unsafe.Pointer(&out)))
			tracer.Write([]byte("get " + ustr.Int(isize, -10) + " " + ustr.Int(size, -10) + " 0x" + ustr.Hex(address) + "  " + filepath.Base(file) + " #" + strconv.Itoa(line) + "\n"))
		}
	}
	return
}

func Put(in []byte) {
	if in == nil || cap(in) <= 0 {
		return
	}
	size, bits := cap(in), uint(0)
	if tracer != nil && (low == -1 || size >= low) && (high == -1 || size <= high) {
		if _, file, line, ok := runtime.Caller(1); ok {
			address := make([]byte, 8)
			binary.BigEndian.PutUint64(address, *(*uint64)(unsafe.Pointer(&in)))
			tracer.Write([]byte("put " + ustr.Int(size, -10) + "            0x" + ustr.Hex(address) + "  " + filepath.Base(file) + " #" + strconv.Itoa(line) + "\n"))
		}
	}
	for size != 0 {
		size >>= 1
		bits++
	}
	size = 1 << (bits - 1)
	if size > 0 && float64(cap(in))/float64(size) <= 1.25 {
		if slab, exists := slabs[size]; exists {
			atomic.AddUint32(&(slab.put), 1)
			select {
			case slab.queue <- in:

			default:
				atomic.AddUint32(&(slab.lost), 1)
			}
		} else {
			atomic.AddUint32(&(slabs[0].put), 1)
			atomic.AddUint32(&(slabs[0].lost), uint32(cap(in)))
		}
	} else {
		atomic.AddUint32(&(slabs[0].put), 1)
		atomic.AddUint32(&(slabs[0].lost), uint32(cap(in)))
	}
}
