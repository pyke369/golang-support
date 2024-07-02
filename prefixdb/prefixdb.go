package prefixdb

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const VERSION = 0x00010000

type fame struct {
	fame  int
	value any
}
type byfame []*fame

func (a byfame) Len() int           { return len(a) }
func (a byfame) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byfame) Less(i, j int) bool { return a[i].fame > a[j].fame }

type node struct {
	down     [2]*node
	up       *node
	data     []uint64
	offset   int
	explored [4]bool
	emitted  bool
	id       int
}
type cluster struct {
	values [3]int   // fame / initial index / final index
	pairs  []uint64 // cluster pairs
	data   []byte   // reduced cluster pairs
}
type PrefixDB struct {
	sync.RWMutex
	tree        node
	strings     map[string]*[3]int  // fame / initial index / final index
	numbers     map[float64]*[3]int // fame / initial index / final index
	pairs       map[uint64]*[3]int  // fame / initial index / final index
	clusters    map[[16]byte]*cluster
	data        []byte
	Total       int
	Version     uint32
	Path        string
	Description string
	Strings     [4]int // size / count / offset / strings index width (bytes)
	Numbers     [3]int // size / count / offset
	Pairs       [3]int // size / count / offset
	Clusters    [4]int // size / count / offset / clusters index width (bytes)
	Maps        [3]int // size / count / offset
	Nodes       [4]int // size / count / offset / nodes width (bits)
}

func New() *PrefixDB {
	return &PrefixDB{strings: map[string]*[3]int{}, numbers: map[float64]*[3]int{}, pairs: map[uint64]*[3]int{}, clusters: map[[16]byte]*cluster{}}
}

func (d *PrefixDB) Add(prefix netip.Prefix, data map[string]any, clusters [][]string) {
	address, ones := prefix.Addr(), prefix.Bits()
	if address.Is4() {
		address = netip.AddrFrom16(address.As16())
		ones += 96
	}
	bits := address.As16()
	d.Lock()
	pnode := &d.tree
	for bit := 0; bit < ones; bit++ {
		down := 0
		if (bits[bit/8] & (1 << (7 - (byte(bit) % 8)))) != 0 {
			down = 1
		}
		if pnode.down[down] == nil {
			pnode.down[down] = &node{}
			pnode.down[down].up = pnode
		}
		if len(pnode.data) != 0 {
			pnode.data = []uint64{}
		}
		pnode = pnode.down[down]
	}

	skeys, ckeys, lkeys := "", [][]string{}, []string{}
	for _, cluster := range clusters {
		skeys += strings.Join(cluster, ` `) + ` `
		ckeys = append(ckeys, cluster)
	}
	for key := range data {
		if !strings.Contains(skeys, key) {
			lkeys = append(lkeys, key)
		}
	}
	ckeys = append(ckeys, lkeys)
	for cindex, keys := range ckeys {
		cpairs := []uint64{}
		for _, key := range keys {
			if len(key) > 255 {
				continue
			}
			if value, exists := data[key]; exists {
				index := 0
				if _, exists := d.strings[key]; !exists {
					index = len(d.strings)
					d.strings[key] = &[3]int{1, index}
				} else {
					index = d.strings[key][1]
					d.strings[key][0]++
				}
				pair := uint64((uint32(index)&0x0fffffff)|0x10000000) << 32
				if tvalue, ok := value.(string); ok {
					if len(tvalue) <= 255 {
						index = 0
						if _, exists := d.strings[tvalue]; !exists {
							index = len(d.strings)
							d.strings[tvalue] = &[3]int{1, index}
						} else {
							index = d.strings[tvalue][1]
							d.strings[tvalue][0]++
						}
						pair |= uint64((uint32(index) & 0x0fffffff) | 0x10000000)
					} else {
						pair |= uint64(0x50000000)
					}
				} else if tvalue, ok := value.(float64); ok {
					index = 0
					if _, exists := d.numbers[tvalue]; !exists {
						index = len(d.numbers)
						d.numbers[tvalue] = &[3]int{1, index}
					} else {
						index = d.numbers[tvalue][1]
						d.numbers[tvalue][0]++
					}
					pair |= uint64((uint32(index) & 0x0fffffff) | 0x20000000)
				} else if tvalue, ok := value.(bool); ok {
					if tvalue {
						pair |= uint64(0x30000000)
					} else {
						pair |= uint64(0x40000000)
					}
				} else {
					pair |= uint64(0x50000000)
				}
				if _, exists := d.pairs[pair]; !exists {
					index = len(d.pairs)
					d.pairs[pair] = &[3]int{1, index}
				} else {
					d.pairs[pair][0]++
				}
				if cindex < len(ckeys)-1 {
					cpairs = append(cpairs, pair)
				} else {
					pnode.data = append(pnode.data, pair)
				}
			}
		}
		if len(cpairs) != 0 {
			buffer := make([]byte, len(cpairs)*8)
			for index, value := range cpairs {
				binary.BigEndian.PutUint64(buffer[index*8:], value)
			}
			key := md5.Sum(buffer)
			index := 0
			if _, exists := d.clusters[key]; !exists {
				index = len(d.clusters)
				d.clusters[key] = &cluster{pairs: cpairs, values: [3]int{1, index}}
			} else {
				index = d.clusters[key].values[1]
				d.clusters[key].values[0]++
			}
			pnode.data = append(pnode.data, 0x7000000000000000|((uint64(index)<<32)&0x0fffffff00000000))
		}
	}
	d.Unlock()
}

func wbytes(bytes, value int, data []byte) {
	if len(data) >= bytes {
		for index := bytes - 1; index >= 0; index-- {
			data[bytes-index-1] = byte(value >> (uint(index * 8)))
		}
	}
}
func wpbits(prefix byte, value int) []byte {
	if value <= 7 {
		return []byte{prefix | (byte(value) & 0x07)}
	}
	bytes := int(math.Ceil(math.Ceil(math.Log2(float64(value+1))) / 8))
	data := []byte{prefix | 0x08 | byte(bytes)}
	for nibble := bytes - 1; nibble >= 0; nibble-- {
		data = append(data, byte(value>>(uint(nibble*8))))
	}
	return data
}
func wnbits(bits, value0, value1 int, data []byte) {
	if bits >= 8 && bits <= 32 && bits%4 == 0 && len(data) >= bits/4 {
		switch bits {
		case 8:
			data[0], data[1] = byte(value0), byte(value1)
		case 12:
			data[0], data[1], data[2] = byte(value0>>4), byte(value0<<4)|(byte(value1>>8)&0x0f), byte(value1)
		case 16:
			binary.BigEndian.PutUint16(data[0:], uint16(value0))
			binary.BigEndian.PutUint16(data[2:], uint16(value1))
		case 20:
			data[0], data[1] = byte(value0>>12), byte(value0>>4)
			data[2] = byte(value0<<4) | (byte(value1>>16) & 0x0f)
			data[3], data[4] = byte(value1>>8), byte(value1)
		case 24:
			data[0], data[1], data[2] = byte(value0>>16), byte(value0>>8), byte(value0)
			data[3], data[4], data[5] = byte(value1>>16), byte(value1>>8), byte(value1)
		case 28:
			data[0], data[1], data[2] = byte(value0>>20), byte(value0>>12), byte(value0>>4)
			data[3] = byte(value0<<4) | (byte(value1>>24) & 0x0f)
			data[4], data[5], data[6] = byte(value1>>16), byte(value1>>8), byte(value1)
		case 32:
			binary.BigEndian.PutUint32(data[0:], uint32(value0))
			binary.BigEndian.PutUint32(data[4:], uint32(value1))
		}
	}
}
func (d *PrefixDB) Save(path, description string) (content []byte, err error) {
	// layout header + signature placeholder + description
	d.Lock()
	d.data = []byte{'P', 'F', 'D', 'B', 0, (VERSION >> 16) & 0xff, (VERSION >> 8) & 0xff, (VERSION & 0xff),
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'D', 'E', 'S', 'C', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if description == "" {
		description = time.Now().Format(`20060102150405`)
	}
	d.Description = description
	copy(d.data[28:47], []byte(description))

	// layout strings dictionary (ordered by fame)
	d.Strings[0] = 0
	for key := range d.strings {
		d.Strings[0] += len(key)
	}
	d.Strings[3] = int(math.Ceil(math.Ceil(math.Log2(float64(d.Strings[0]+1))) / 8))
	d.data = append(d.data, []byte{'S', 'T', 'R', 'S', byte(d.Strings[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	d.Strings[2] = len(d.data)
	d.Strings[1] = len(d.strings)
	d.Strings[0] += d.Strings[1] * d.Strings[3]
	flist := make([]*fame, d.Strings[1])
	for key, values := range d.strings {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	d.data = append(d.data, make([]byte, d.Strings[1]*d.Strings[3])...)
	offset := 0
	for index, item := range flist {
		d.strings[item.value.(string)][2] = index
		d.data = append(d.data, []byte(item.value.(string))...)
		wbytes(d.Strings[3], offset, d.data[d.Strings[2]+(index*d.Strings[3]):])
		offset += len(item.value.(string))
	}
	binary.BigEndian.PutUint32(d.data[d.Strings[2]-8:], uint32(d.Strings[0]))
	binary.BigEndian.PutUint32(d.data[d.Strings[2]-4:], uint32(d.Strings[1]))
	strings := make([]*fame, d.Strings[1])
	for key, values := range d.strings {
		strings[values[1]] = &fame{values[0], key}
	}

	// layout numbers dictionary (ordered by fame)
	d.data = append(d.data, []byte{'N', 'U', 'M', 'S', 0, 0, 0, 0, 0, 0, 0, 0}...)
	d.Numbers[2] = len(d.data)
	d.Numbers[1] = len(d.numbers)
	d.Numbers[0] = d.Numbers[1] * 8
	flist = make([]*fame, d.Numbers[1])
	for key, values := range d.numbers {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	d.data = append(d.data, make([]byte, d.Numbers[1]*8)...)
	for index, item := range flist {
		d.numbers[item.value.(float64)][2] = index
		binary.BigEndian.PutUint64(d.data[d.Numbers[2]+(index*8):], math.Float64bits(item.value.(float64)))
	}
	binary.BigEndian.PutUint32(d.data[d.Numbers[2]-8:], uint32(d.Numbers[0]))
	binary.BigEndian.PutUint32(d.data[d.Numbers[2]-4:], uint32(d.Numbers[1]))
	numbers := make([]*fame, d.Numbers[1])
	for key, values := range d.numbers {
		numbers[values[1]] = &fame{values[0], key}
	}

	// layout pairs dictionary (ordered by fame)
	d.data = append(d.data, []byte{'P', 'A', 'I', 'R', 0, 0, 0, 0, 0, 0, 0, 0}...)
	d.Pairs[2] = len(d.data)
	flist = make([]*fame, len(d.pairs))
	for key, values := range d.pairs {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	for index, item := range flist {
		if item.fame > 1 {
			d.pairs[item.value.(uint64)][2] = index
		} else {
			delete(d.pairs, item.value.(uint64))
		}
	}
	d.Pairs[1] = len(d.pairs)
	d.Pairs[0] = d.Pairs[1] * 8
	d.data = append(d.data, make([]byte, d.Pairs[0])...)
	for index, item := range flist {
		if item.fame <= 1 {
			break
		}
		pair := 0x1000000000000000 | (uint64(d.strings[strings[(item.value.(uint64)>>32)&0x0fffffff].value.(string)][2]) << 32)
		switch (item.value.(uint64) & 0xf0000000) >> 28 {
		case 1:
			pair |= 0x10000000 | uint64(d.strings[strings[item.value.(uint64)&0x0fffffff].value.(string)][2])
		case 2:
			pair |= 0x20000000 | uint64(d.numbers[numbers[item.value.(uint64)&0x0fffffff].value.(float64)][2])
		default:
			pair |= item.value.(uint64) & 0xf0000000
		}
		binary.BigEndian.PutUint64(d.data[d.Pairs[2]+(index*8):], pair)
	}
	binary.BigEndian.PutUint32(d.data[d.Pairs[2]-8:], uint32(d.Pairs[0]))
	binary.BigEndian.PutUint32(d.data[d.Pairs[2]-4:], uint32(d.Pairs[1]))

	// layout clusters dictionary (ordered by fame, and reduced for strings, numbers and pairs)
	d.Clusters[0] = 0
	for _, cluster := range d.clusters {
		for _, pair := range cluster.pairs {
			if _, exists := d.pairs[pair]; exists {
				cluster.data = append(cluster.data, wpbits(0x60, d.pairs[pair][2])...)
			} else {
				cluster.data = append(cluster.data, wpbits(0x10, d.strings[strings[(pair>>32)&0x0fffffff].value.(string)][2])...)
				switch (pair & 0xf0000000) >> 28 {
				case 1:
					cluster.data = append(cluster.data, wpbits(0x10, d.strings[strings[pair&0x0fffffff].value.(string)][2])...)
				case 2:
					cluster.data = append(cluster.data, wpbits(0x20, d.numbers[numbers[pair&0x0fffffff].value.(float64)][2])...)
				default:
					cluster.data = append(cluster.data, byte((pair&0xf0000000)>>24))
				}
			}
		}
		d.Clusters[0] += len(cluster.data)
	}
	d.Clusters[3] = int(math.Ceil(math.Ceil(math.Log2(float64(d.Clusters[0]+1))) / 8))
	d.data = append(d.data, []byte{'C', 'L', 'U', 'S', byte(d.Clusters[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	d.Clusters[2] = len(d.data)
	d.Clusters[1] = len(d.clusters)
	d.Clusters[0] += d.Clusters[1] * d.Clusters[3]
	flist = make([]*fame, d.Clusters[1])
	for key, cluster := range d.clusters {
		flist[cluster.values[1]] = &fame{cluster.values[0], key}
	}
	sort.Sort(byfame(flist))
	d.data = append(d.data, make([]byte, d.Clusters[1]*d.Clusters[3])...)
	offset = 0
	for index, item := range flist {
		d.clusters[item.value.([16]byte)].values[2] = index
		d.data = append(d.data, d.clusters[item.value.([16]byte)].data...)
		wbytes(d.Clusters[3], offset, d.data[d.Clusters[2]+(index*d.Clusters[3]):])
		offset += len(d.clusters[item.value.([16]byte)].data)
	}
	binary.BigEndian.PutUint32(d.data[d.Clusters[2]-8:], uint32(d.Clusters[0]))
	binary.BigEndian.PutUint32(d.data[d.Clusters[2]-4:], uint32(d.Clusters[1]))
	clusters := make([]*fame, d.Clusters[1])
	for key, cluster := range d.clusters {
		clusters[cluster.values[1]] = &fame{cluster.values[0], key}
	}

	// layout maps dictionary (reduced for strings, numbers, pairs and clusters)
	d.Nodes[1] = 1
	d.data = append(d.data, []byte{'M', 'A', 'P', 'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}...)
	pnode := &d.tree
	d.Maps[2] = len(d.data) - 2
	d.Maps[1] = 1
	d.Maps[0] = 2
	for {
		if pnode.down[0] != nil && !pnode.explored[0] {
			pnode.explored[0] = true
			pnode = pnode.down[0]
		} else if pnode.down[1] != nil && !pnode.explored[1] {
			pnode.explored[1] = true
			pnode = pnode.down[1]
		} else if pnode.up != nil {
			pnode = pnode.up
		}
		if pnode.up == nil {
			break
		}
		if pnode.down[0] == nil && pnode.down[1] == nil {
			if len(pnode.data) == 0 {
				pnode.offset = 1
			} else {
				data := []byte{}
				for index := 0; index < len(pnode.data); index++ {
					last := byte(0x00)
					if index == len(pnode.data)-1 {
						last = 0x80
					}
					if ((pnode.data[index]>>32)&0xf0000000)>>28 == 7 {
						data = append(data, wpbits(last|0x70, d.clusters[clusters[(pnode.data[index]>>32)&0x0fffffff].value.([16]byte)].values[2])...)
					} else {
						if _, exists := d.pairs[pnode.data[index]]; exists {
							data = append(data, wpbits(last|0x60, d.pairs[pnode.data[index]][2])...)
						} else {
							data = append(data, wpbits(0x10, d.strings[strings[(pnode.data[index]>>32)&0x0fffffff].value.(string)][2])...)
							switch (pnode.data[index] & 0xf0000000) >> 28 {
							case 1:
								data = append(data, wpbits(last|0x10, d.strings[strings[pnode.data[index]&0x0fffffff].value.(string)][2])...)
							case 2:
								data = append(data, wpbits(last|0x20, d.numbers[numbers[pnode.data[index]&0x0fffffff].value.(float64)][2])...)
							default:
								data = append(data, last|byte((pnode.data[index]&0xf0000000)>>24))
							}
						}
					}
				}
				d.data = append(d.data, data...)
				pnode.offset = d.Maps[0]
				d.Maps[0] += len(data)
				d.Maps[1]++
			}
		} else if pnode.id == 0 {
			pnode.id = d.Nodes[1]
			d.Nodes[1]++
		}
	}
	binary.BigEndian.PutUint32(d.data[d.Maps[2]-8:], uint32(d.Maps[0]))
	binary.BigEndian.PutUint32(d.data[d.Maps[2]-4:], uint32(d.Maps[1]))

	// layout nodes tree
	d.Nodes[3] = int(math.Ceil(math.Ceil(math.Log2(float64(d.Nodes[1]+d.Maps[0]+1)))/4) * 4)
	d.data = append(d.data, []byte{'N', 'O', 'D', 'E', byte(d.Nodes[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	d.Nodes[2] = len(d.data)
	d.Nodes[0] = d.Nodes[1] * ((2 * d.Nodes[3]) / 8)
	d.data = append(d.data, make([]byte, d.Nodes[0])...)
	pnode = &d.tree
	next := [2]int{}
	for {
		if (pnode == &d.tree || pnode.id != 0) && !pnode.emitted {
			pnode.emitted = true
			for index := 0; index <= 1; index++ {
				next[index] = d.Nodes[1]
				if pnode.down[index] != nil {
					if pnode.down[index].id != 0 {
						next[index] = pnode.down[index].id
					} else {
						next[index] += pnode.down[index].offset
					}
				}
			}
			wnbits(d.Nodes[3], next[0], next[1], d.data[d.Nodes[2]+(pnode.id*((2*d.Nodes[3])/8)):])
		}
		if pnode.down[0] != nil && !pnode.explored[2] {
			pnode.explored[2] = true
			pnode = pnode.down[0]
		} else if pnode.down[1] != nil && !pnode.explored[3] {
			pnode.explored[3] = true
			pnode = pnode.down[1]
		} else if pnode.up != nil {
			pnode = pnode.up
		}
		if pnode.up == nil {
			break
		}
	}
	binary.BigEndian.PutUint32(d.data[d.Nodes[2]-8:], uint32(d.Nodes[0]))
	binary.BigEndian.PutUint32(d.data[d.Nodes[2]-4:], uint32(d.Nodes[1]))

	// finalize header
	d.tree, d.strings, d.numbers, d.pairs, d.clusters = node{}, map[string]*[3]int{}, map[float64]*[3]int{}, map[uint64]*[3]int{}, map[[16]byte]*cluster{}
	hash := md5.Sum(d.data[24:])
	copy(d.data[8:], hash[:])
	d.Total = len(d.data)

	// save database
	if path != "" {
		if path == "-" {
			_, err = os.Stdout.Write(d.data)
		} else {
			err = os.WriteFile(path, d.data, 0644)
		}
	}

	d.Unlock()
	return d.data, err
}

func (d *PrefixDB) Load(path string) error {
	if data, err := os.ReadFile(path); err != nil {
		return err
	} else {
		if len(data) < 8 || string(data[0:4]) != "PFDB" {
			return errors.New(`prefixdb: invalid preamble`)
		}
		if version := (uint32(data[5]) << 16) + (uint32(data[6]) << 8) + uint32(data[7]); (version & 0xff0000) > (VERSION & 0xff0000) {
			return errors.New("prefixdb: incompatible library and database major versions")
		} else {
			hash := md5.Sum(data[24:])
			if len(data) < 24 || slices.Compare(hash[:], data[8:24]) != 0 {
				return errors.New(`prefixdb: checksum is invalid`)
			}
			d.Lock()
			d.data = data
			d.Total = len(data)
			d.Version = version
			d.Path = path
			offset := 24
			if d.Total >= offset+4 && string(data[offset:offset+4]) == "DESC" {
				offset += 4
				if d.Total >= offset+20 {
					index := 0
					if index = bytes.Index(data[offset:offset+20], []byte{0}); index < 0 {
						index = 20
					}
					d.Description = string(data[offset : offset+index])
					offset += 20
					if d.Total >= offset+4 && string(data[offset:offset+4]) == "STRS" {
						offset += 4
						if d.Total >= offset+9 {
							d.Strings[3] = int(data[offset])
							d.Strings[2] = offset + 9
							d.Strings[1] = int(binary.BigEndian.Uint32(d.data[offset+5:]))
							d.Strings[0] = int(binary.BigEndian.Uint32(d.data[offset+1:]))
							offset += 9 + d.Strings[0]
							if d.Total >= offset+4 && string(data[offset:offset+4]) == "NUMS" {
								offset += 4
								if d.Total >= offset+8 {
									d.Numbers[2] = offset + 8
									d.Numbers[1] = int(binary.BigEndian.Uint32(d.data[offset+4:]))
									d.Numbers[0] = int(binary.BigEndian.Uint32(d.data[offset:]))
									offset += 8 + d.Numbers[0]
									if d.Total >= offset+4 && string(data[offset:offset+4]) == "PAIR" {
										offset += 4
										if d.Total >= offset+8 {
											d.Pairs[2] = offset + 8
											d.Pairs[1] = int(binary.BigEndian.Uint32(d.data[offset+4:]))
											d.Pairs[0] = int(binary.BigEndian.Uint32(d.data[offset:]))
											offset += 8 + d.Pairs[0]
											if d.Total >= offset+4 && string(data[offset:offset+4]) == "CLUS" {
												offset += 4
												d.Clusters[3] = int(data[offset])
												d.Clusters[2] = offset + 9
												d.Clusters[1] = int(binary.BigEndian.Uint32(d.data[offset+5:]))
												d.Clusters[0] = int(binary.BigEndian.Uint32(d.data[offset+1:]))
												offset += 9 + d.Clusters[0]
												if d.Total >= offset+4 && string(data[offset:offset+4]) == "MAPS" {
													offset += 4
													if d.Total >= offset+8 {
														d.Maps[2] = offset + 8
														d.Maps[1] = int(binary.BigEndian.Uint32(d.data[offset+4:]))
														d.Maps[0] = int(binary.BigEndian.Uint32(d.data[offset:]))
														offset += 8 + d.Maps[0]
														if d.Total >= offset+9 && string(data[offset:offset+4]) == "NODE" {
															offset += 4
															d.Nodes[3] = int(data[offset])
															d.Nodes[2] = offset + 9
															d.Nodes[1] = int(binary.BigEndian.Uint32(d.data[offset+5:]))
															d.Nodes[0] = int(binary.BigEndian.Uint32(d.data[offset+1:]))
															if offset+9+d.Nodes[0] != d.Total {
																d.Nodes[2] = 0
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			d.Unlock()
			if d.Strings[2] == 0 || d.Numbers[2] == 0 || d.Pairs[2] == 0 || d.Clusters[2] == 0 || d.Maps[2] == 0 || d.Nodes[2] == 0 {
				return errors.New(`prefixdb: structure is invalid`)
			}
		}
	}
	return nil
}
func rpbits(data []byte) (section, index, size int, last bool) {
	section = int((data[0] & 0x70) >> 4)
	if data[0]&0x80 != 0 || section == 0 {
		last = true
	}
	if section == 1 || section == 2 || section == 6 || section == 7 {
		if data[0]&0x08 != 0 {
			size = int(data[0] & 0x07)
			for nibble := 1; nibble <= size; nibble++ {
				index |= int(data[nibble]) << (uint(size-nibble) * 8)
			}
		} else {
			index = int(data[0] & 0x07)
		}
	}
	size++
	return section, index, size, last
}
func rnbits(bits, index, down int, data []byte) int {
	if bits >= 8 && bits <= 32 && bits%4 == 0 && (down == 0 || down == 1) && len(data) >= (index+1)*(bits/4) {
		offset := index * (bits / 4)
		switch bits {
		case 8:
			return int(data[offset+down])
		case 12:
			if down == 0 {
				return (int(data[offset]) << 4) | ((int(data[offset+1]) >> 4) & 0x0f)
			} else {
				return ((int(data[offset+1]) & 0x0f) << 8) | int(data[offset+2])
			}
		case 16:
			return int(binary.BigEndian.Uint16(data[offset+(down*2):]))
		case 20:
			if down == 0 {
				return (int(data[offset]) << 12) | (int(data[offset+1]) << 4) | ((int(data[offset+2]) >> 4) & 0x0f)
			} else {
				return ((int(data[offset+2]) & 0x0f) << 16) | (int(data[offset+3]) << 8) | int(data[offset+4])
			}
		case 24:
			if down == 0 {
				return (int(data[offset]) << 16) | (int(data[offset+1]) << 8) | int(data[offset+2])
			} else {
				return (int(data[offset+3]) << 16) | (int(data[offset+4]) << 8) | int(data[offset+5])
			}
		case 28:
			if down == 0 {
				return (int(data[offset]) << 20) | (int(data[offset+1]) << 12) | (int(data[offset+2]) << 4) | ((int(data[offset+3]) >> 4) & 0x0f)
			} else {
				return ((int(data[offset+3]) & 0x0f) << 24) | (int(data[offset+4]) << 16) | (int(data[offset+5]) << 8) | int(data[offset+6])
			}
		case 32:
			return int(binary.BigEndian.Uint32(data[offset+(down*4):]))
		}
	}
	return index
}
func rbytes(width int, data []byte) (value int) {
	for index := 0; index < width; index++ {
		value |= int(data[index]) << (uint(width-1-index) * 8)
	}
	return value
}
func (d *PrefixDB) rstring(index int) string {
	count, offset, width := d.Strings[1], d.Strings[2], d.Strings[3]
	if index >= count {
		return ""
	}
	start, end := rbytes(width, d.data[offset+(index*width):]), 0
	if index < count-1 {
		end = rbytes(width, d.data[offset+(index+1)*width:])
	} else {
		end = d.Strings[0] - (count * width)
	}
	return string(d.data[offset+(count*width)+start : offset+(count*width)+end])
}
func (d *PrefixDB) rnumber(index int) float64 {
	if index >= d.Numbers[1] {
		return 0.0
	}
	return math.Float64frombits(binary.BigEndian.Uint64(d.data[d.Numbers[2]+(index*8):]))
}
func (d *PrefixDB) rpair(index int, pairs map[string]any) {
	if index < d.Pairs[1] {
		pair := binary.BigEndian.Uint64(d.data[d.Pairs[2]+(index*8):])
		if key := d.rstring(int((pair >> 32) & 0x0fffffff)); key != "" {
			switch (pair & 0xf0000000) >> 28 {
			case 1:
				pairs[key] = d.rstring(int(pair & 0x0fffffff))
			case 2:
				pairs[key] = d.rnumber(int(pair & 0x0fffffff))
			case 3:
				pairs[key] = true
			case 4:
				pairs[key] = false
			}
		}
	}
}
func (d *PrefixDB) rcluster(index int, pairs map[string]any) {
	count, offset, width := d.Clusters[1], d.Clusters[2], d.Clusters[3]
	if index < count {
		start, end := rbytes(width, d.data[offset+(index*width):]), 0
		if index < count-1 {
			end = rbytes(width, d.data[offset+(index+1)*width:])
		} else {
			end = d.Clusters[0] - (count * width)
		}
		start += offset + (count * width)
		end += offset + (count * width)
		key := ""
		for start < end {
			section, index, size, _ := rpbits(d.data[start:])
			switch section {
			case 1:
				if key != "" {
					pairs[key] = d.rstring(index)
					key = ""
				} else {
					key = d.rstring(index)
				}
			case 2:
				if key != "" {
					pairs[key] = d.rnumber(index)
					key = ""
				}
			case 3:
				if key != "" {
					pairs[key] = true
					key = ""
				}
			case 4:
				if key != "" {
					pairs[key] = false
					key = ""
				}
			case 5:
				if key != "" {
					pairs[key] = nil
					key = ""
				}
			case 6:
				d.rpair(index, pairs)
			}
			start += size
		}
	}
}
func (d *PrefixDB) Lookup(value string, out map[string]any) {
	if out == nil || d.data == nil || d.Total == 0 || d.Version == 0 || d.Strings[2] == 0 || d.Numbers[2] == 0 ||
		d.Pairs[2] == 0 || d.Clusters[2] == 0 || d.Maps[2] == 0 || d.Nodes[2] == 0 || value == "" {
		return
	}
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		return
	}
	address, offset := parsed.As16(), 0
	d.RLock()
	for bit := 0; bit < 128; bit++ {
		down := 0
		if (address[bit/8] & (1 << (7 - (byte(bit) % 8)))) != 0 {
			down = 1
		}
		offset = rnbits(d.Nodes[3], offset, down, d.data[d.Nodes[2]:])
		if offset == d.Nodes[1] || offset == 0 {
			break
		}
		if offset > d.Nodes[1] {
			offset -= d.Nodes[1]
			if offset < d.Maps[0] {
				offset += d.Maps[2]
				key := ""
				for offset < d.Maps[2]+d.Maps[0] {
					section, index, size, last := rpbits(d.data[offset:])
					switch section {
					case 1:
						if key != "" {
							out[key] = d.rstring(index)
							key = ""
						} else {
							key = d.rstring(index)
						}
					case 2:
						if key != "" {
							out[key] = d.rnumber(index)
							key = ""
						}
					case 3:
						if key != "" {
							out[key] = true
							key = ""
						}
					case 4:
						if key != "" {
							out[key] = false
							key = ""
						}
					case 5:
						if key != "" {
							out[key] = nil
							key = ""
						}
					case 6:
						d.rpair(index, out)
					case 7:
						d.rcluster(index, out)
					}
					if last {
						break
					}
					offset += size
				}
			}
			break
		}
	}
	d.RUnlock()
	if country, ok := out["country_code"].(string); ok && country != "" {
		if value, ok := out["latitude"].(float64); ok && value == 0.0 {
			if value, ok := out["longitude"].(float64); ok && value == 0.0 {
				if position, exists := capitals[country]; exists {
					out["latitude"], out["longitude"] = position[0], position[1]
				}
			}
		}
	}
}
