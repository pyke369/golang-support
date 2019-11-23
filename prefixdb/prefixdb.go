package prefixdb

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const VERSION = 0x00010000

type fame struct {
	fame  int
	value interface{}
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

func (this *PrefixDB) Add(prefix net.IPNet, data map[string]interface{}, clusters [][]string) {
	prefix.IP = prefix.IP.To16()
	ones, bits := prefix.Mask.Size()
	if bits == 32 {
		ones += 96
		prefix.Mask = net.CIDRMask(ones, bits+96)
	}
	this.Lock()
	pnode := &this.tree
	for bit := 0; bit < ones; bit++ {
		down := 0
		if (prefix.IP[bit/8] & (1 << (7 - (byte(bit) % 8)))) != 0 {
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
	for key, _ := range data {
		if strings.Index(skeys, key) < 0 {
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
			if value, ok := data[key]; ok {
				index := 0
				if _, ok := this.strings[key]; !ok {
					index = len(this.strings)
					this.strings[key] = &[3]int{1, index}
				} else {
					index = this.strings[key][1]
					this.strings[key][0]++
				}
				pair := uint64((uint32(index)&0x0fffffff)|0x10000000) << 32
				if tvalue, ok := value.(string); ok {
					if len(tvalue) <= 255 {
						index = 0
						if _, ok := this.strings[tvalue]; !ok {
							index = len(this.strings)
							this.strings[tvalue] = &[3]int{1, index}
						} else {
							index = this.strings[tvalue][1]
							this.strings[tvalue][0]++
						}
						pair |= uint64((uint32(index) & 0x0fffffff) | 0x10000000)
					} else {
						pair |= uint64(0x50000000)
					}
				} else if tvalue, ok := value.(float64); ok {
					index = 0
					if _, ok := this.numbers[tvalue]; !ok {
						index = len(this.numbers)
						this.numbers[tvalue] = &[3]int{1, index}
					} else {
						index = this.numbers[tvalue][1]
						this.numbers[tvalue][0]++
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
				if _, ok := this.pairs[pair]; !ok {
					index = len(this.pairs)
					this.pairs[pair] = &[3]int{1, index}
				} else {
					this.pairs[pair][0]++
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
			if _, ok := this.clusters[key]; !ok {
				index = len(this.clusters)
				this.clusters[key] = &cluster{pairs: cpairs, values: [3]int{1, index}}
			} else {
				index = this.clusters[key].values[1]
				this.clusters[key].values[0]++
			}
			pnode.data = append(pnode.data, 0x7000000000000000|((uint64(index)<<32)&0x0fffffff00000000))
		}
	}
	this.Unlock()
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
func (this *PrefixDB) Save(path, description string) (content []byte, err error) {
	// layout header + signature placeholder + description
	this.Lock()
	this.data = []byte{'P', 'F', 'D', 'B', 0, (VERSION >> 16) & 0xff, (VERSION >> 8) & 0xff, (VERSION & 0xff),
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'D', 'E', 'S', 'C', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if description == "" {
		description = time.Now().Format(`20060102150405`)
	}
	this.Description = description
	copy(this.data[28:47], []byte(description))

	// layout strings dictionary (ordered by fame)
	this.Strings[0] = 0
	for key, _ := range this.strings {
		this.Strings[0] += len(key)
	}
	this.Strings[3] = int(math.Ceil(math.Ceil(math.Log2(float64(this.Strings[0]+1))) / 8))
	this.data = append(this.data, []byte{'S', 'T', 'R', 'S', byte(this.Strings[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	this.Strings[2] = len(this.data)
	this.Strings[1] = len(this.strings)
	this.Strings[0] += this.Strings[1] * this.Strings[3]
	flist := make([]*fame, this.Strings[1])
	for key, values := range this.strings {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	this.data = append(this.data, make([]byte, this.Strings[1]*this.Strings[3])...)
	offset := 0
	for index, item := range flist {
		this.strings[item.value.(string)][2] = index
		this.data = append(this.data, []byte(item.value.(string))...)
		wbytes(this.Strings[3], offset, this.data[this.Strings[2]+(index*this.Strings[3]):])
		offset += len(item.value.(string))
	}
	binary.BigEndian.PutUint32(this.data[this.Strings[2]-8:], uint32(this.Strings[0]))
	binary.BigEndian.PutUint32(this.data[this.Strings[2]-4:], uint32(this.Strings[1]))
	strings := make([]*fame, this.Strings[1])
	for key, values := range this.strings {
		strings[values[1]] = &fame{values[0], key}
	}

	// layout numbers dictionary (ordered by fame)
	this.data = append(this.data, []byte{'N', 'U', 'M', 'S', 0, 0, 0, 0, 0, 0, 0, 0}...)
	this.Numbers[2] = len(this.data)
	this.Numbers[1] = len(this.numbers)
	this.Numbers[0] = this.Numbers[1] * 8
	flist = make([]*fame, this.Numbers[1])
	for key, values := range this.numbers {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	this.data = append(this.data, make([]byte, this.Numbers[1]*8)...)
	for index, item := range flist {
		this.numbers[item.value.(float64)][2] = index
		binary.BigEndian.PutUint64(this.data[this.Numbers[2]+(index*8):], math.Float64bits(item.value.(float64)))
	}
	binary.BigEndian.PutUint32(this.data[this.Numbers[2]-8:], uint32(this.Numbers[0]))
	binary.BigEndian.PutUint32(this.data[this.Numbers[2]-4:], uint32(this.Numbers[1]))
	numbers := make([]*fame, this.Numbers[1])
	for key, values := range this.numbers {
		numbers[values[1]] = &fame{values[0], key}
	}

	// layout pairs dictionary (ordered by fame)
	this.data = append(this.data, []byte{'P', 'A', 'I', 'R', 0, 0, 0, 0, 0, 0, 0, 0}...)
	this.Pairs[2] = len(this.data)
	flist = make([]*fame, len(this.pairs))
	for key, values := range this.pairs {
		flist[values[1]] = &fame{values[0], key}
	}
	sort.Sort(byfame(flist))
	for index, item := range flist {
		if item.fame > 1 {
			this.pairs[item.value.(uint64)][2] = index
		} else {
			delete(this.pairs, item.value.(uint64))
		}
	}
	this.Pairs[1] = len(this.pairs)
	this.Pairs[0] = this.Pairs[1] * 8
	this.data = append(this.data, make([]byte, this.Pairs[0])...)
	for index, item := range flist {
		if item.fame <= 1 {
			break
		}
		pair := 0x1000000000000000 | (uint64(this.strings[strings[(item.value.(uint64)>>32)&0x0fffffff].value.(string)][2]) << 32)
		switch (item.value.(uint64) & 0xf0000000) >> 28 {
		case 1:
			pair |= 0x10000000 | uint64(this.strings[strings[item.value.(uint64)&0x0fffffff].value.(string)][2])
		case 2:
			pair |= 0x20000000 | uint64(this.numbers[numbers[item.value.(uint64)&0x0fffffff].value.(float64)][2])
		default:
			pair |= item.value.(uint64) & 0xf0000000
		}
		binary.BigEndian.PutUint64(this.data[this.Pairs[2]+(index*8):], pair)
	}
	binary.BigEndian.PutUint32(this.data[this.Pairs[2]-8:], uint32(this.Pairs[0]))
	binary.BigEndian.PutUint32(this.data[this.Pairs[2]-4:], uint32(this.Pairs[1]))

	// layout clusters dictionary (ordered by fame, and reduced for strings, numbers and pairs)
	this.Clusters[0] = 0
	for _, cluster := range this.clusters {
		for _, pair := range cluster.pairs {
			if _, ok := this.pairs[pair]; ok {
				cluster.data = append(cluster.data, wpbits(0x60, this.pairs[pair][2])...)
			} else {
				cluster.data = append(cluster.data, wpbits(0x10, this.strings[strings[(pair>>32)&0x0fffffff].value.(string)][2])...)
				switch (pair & 0xf0000000) >> 28 {
				case 1:
					cluster.data = append(cluster.data, wpbits(0x10, this.strings[strings[pair&0x0fffffff].value.(string)][2])...)
				case 2:
					cluster.data = append(cluster.data, wpbits(0x20, this.numbers[numbers[pair&0x0fffffff].value.(float64)][2])...)
				default:
					cluster.data = append(cluster.data, byte((pair&0xf0000000)>>24))
				}
			}
		}
		this.Clusters[0] += len(cluster.data)
	}
	this.Clusters[3] = int(math.Ceil(math.Ceil(math.Log2(float64(this.Clusters[0]+1))) / 8))
	this.data = append(this.data, []byte{'C', 'L', 'U', 'S', byte(this.Clusters[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	this.Clusters[2] = len(this.data)
	this.Clusters[1] = len(this.clusters)
	this.Clusters[0] += this.Clusters[1] * this.Clusters[3]
	flist = make([]*fame, this.Clusters[1])
	for key, cluster := range this.clusters {
		flist[cluster.values[1]] = &fame{cluster.values[0], key}
	}
	sort.Sort(byfame(flist))
	this.data = append(this.data, make([]byte, this.Clusters[1]*this.Clusters[3])...)
	offset = 0
	for index, item := range flist {
		this.clusters[item.value.([16]byte)].values[2] = index
		this.data = append(this.data, this.clusters[item.value.([16]byte)].data...)
		wbytes(this.Clusters[3], offset, this.data[this.Clusters[2]+(index*this.Clusters[3]):])
		offset += len(this.clusters[item.value.([16]byte)].data)
	}
	binary.BigEndian.PutUint32(this.data[this.Clusters[2]-8:], uint32(this.Clusters[0]))
	binary.BigEndian.PutUint32(this.data[this.Clusters[2]-4:], uint32(this.Clusters[1]))
	clusters := make([]*fame, this.Clusters[1])
	for key, cluster := range this.clusters {
		clusters[cluster.values[1]] = &fame{cluster.values[0], key}
	}

	// layout maps dictionary (reduced for strings, numbers, pairs and clusters)
	this.Nodes[1] = 1
	this.data = append(this.data, []byte{'M', 'A', 'P', 'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}...)
	pnode := &this.tree
	this.Maps[2] = len(this.data) - 2
	this.Maps[1] = 1
	this.Maps[0] = 2
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
						data = append(data, wpbits(last|0x70, this.clusters[clusters[(pnode.data[index]>>32)&0x0fffffff].value.([16]byte)].values[2])...)
					} else {
						if _, ok := this.pairs[pnode.data[index]]; ok {
							data = append(data, wpbits(last|0x60, this.pairs[pnode.data[index]][2])...)
						} else {
							data = append(data, wpbits(0x10, this.strings[strings[(pnode.data[index]>>32)&0x0fffffff].value.(string)][2])...)
							switch (pnode.data[index] & 0xf0000000) >> 28 {
							case 1:
								data = append(data, wpbits(last|0x10, this.strings[strings[pnode.data[index]&0x0fffffff].value.(string)][2])...)
							case 2:
								data = append(data, wpbits(last|0x20, this.numbers[numbers[pnode.data[index]&0x0fffffff].value.(float64)][2])...)
							default:
								data = append(data, last|byte((pnode.data[index]&0xf0000000)>>24))
							}
						}
					}
				}
				this.data = append(this.data, data...)
				pnode.offset = this.Maps[0]
				this.Maps[0] += len(data)
				this.Maps[1]++
			}
		} else if pnode.id == 0 {
			pnode.id = this.Nodes[1]
			this.Nodes[1]++
		}
	}
	binary.BigEndian.PutUint32(this.data[this.Maps[2]-8:], uint32(this.Maps[0]))
	binary.BigEndian.PutUint32(this.data[this.Maps[2]-4:], uint32(this.Maps[1]))

	// layout nodes tree
	this.Nodes[3] = int(math.Ceil(math.Ceil(math.Log2(float64(this.Nodes[1]+this.Maps[0]+1)))/4) * 4)
	this.data = append(this.data, []byte{'N', 'O', 'D', 'E', byte(this.Nodes[3]), 0, 0, 0, 0, 0, 0, 0, 0}...)
	this.Nodes[2] = len(this.data)
	this.Nodes[0] = this.Nodes[1] * ((2 * this.Nodes[3]) / 8)
	this.data = append(this.data, make([]byte, this.Nodes[0])...)
	pnode = &this.tree
	next := [2]int{}
	for {
		if (pnode == &this.tree || pnode.id != 0) && !pnode.emitted {
			pnode.emitted = true
			for index := 0; index <= 1; index++ {
				next[index] = this.Nodes[1]
				if pnode.down[index] != nil {
					if pnode.down[index].id != 0 {
						next[index] = pnode.down[index].id
					} else {
						next[index] += pnode.down[index].offset
					}
				}
			}
			wnbits(this.Nodes[3], next[0], next[1], this.data[this.Nodes[2]+(pnode.id*((2*this.Nodes[3])/8)):])
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
	binary.BigEndian.PutUint32(this.data[this.Nodes[2]-8:], uint32(this.Nodes[0]))
	binary.BigEndian.PutUint32(this.data[this.Nodes[2]-4:], uint32(this.Nodes[1]))

	// finalize header
	this.tree, this.strings, this.numbers, this.pairs, this.clusters = node{}, map[string]*[3]int{}, map[float64]*[3]int{}, map[uint64]*[3]int{}, map[[16]byte]*cluster{}
	hash := md5.Sum(this.data[24:])
	copy(this.data[8:], hash[:])
	this.Total = len(this.data)

	// save database
	if path != "" {
		if path == "-" {
			_, err = os.Stdout.Write(this.data)
		} else {
			err = ioutil.WriteFile(path, this.data, 0644)
		}
	}

	this.Unlock()
	return this.data, err
}

func (this *PrefixDB) Load(path string) error {
	if data, err := ioutil.ReadFile(path); err != nil {
		return err
	} else {
		if len(data) < 8 || string(data[0:4]) != "PFDB" {
			return errors.New(`prefixdb: invalid preamble`)
		}
		if version := (uint32(data[5]) << 16) + (uint32(data[6]) << 8) + uint32(data[7]); (version & 0xff0000) > (VERSION & 0xff0000) {
			return fmt.Errorf(`prefixdb: library major version %d is incompatible with database major version %d`, (VERSION&0xff0000)>>16, (version&0xff0000)>>16)
		} else {
			if len(data) < 24 || fmt.Sprintf("%x", md5.Sum(data[24:])) != fmt.Sprintf("%x", data[8:24]) {
				return errors.New(`prefixdb: checksum is invalid`)
			}
			this.Lock()
			this.data = data
			this.Total = len(data)
			this.Version = version
			offset := 24
			if this.Total >= offset+4 && string(data[offset:offset+4]) == "DESC" {
				offset += 4
				if this.Total >= offset+20 {
					index := 0
					if index = bytes.Index(data[offset:offset+20], []byte{0}); index < 0 {
						index = 20
					}
					this.Description = fmt.Sprintf("%s", data[offset:offset+index])
					offset += 20
					if this.Total >= offset+4 && string(data[offset:offset+4]) == "STRS" {
						offset += 4
						if this.Total >= offset+9 {
							this.Strings[3] = int(data[offset])
							this.Strings[2] = offset + 9
							this.Strings[1] = int(binary.BigEndian.Uint32(this.data[offset+5:]))
							this.Strings[0] = int(binary.BigEndian.Uint32(this.data[offset+1:]))
							offset += 9 + this.Strings[0]
							if this.Total >= offset+4 && string(data[offset:offset+4]) == "NUMS" {
								offset += 4
								if this.Total >= offset+8 {
									this.Numbers[2] = offset + 8
									this.Numbers[1] = int(binary.BigEndian.Uint32(this.data[offset+4:]))
									this.Numbers[0] = int(binary.BigEndian.Uint32(this.data[offset:]))
									offset += 8 + this.Numbers[0]
									if this.Total >= offset+4 && string(data[offset:offset+4]) == "PAIR" {
										offset += 4
										if this.Total >= offset+8 {
											this.Pairs[2] = offset + 8
											this.Pairs[1] = int(binary.BigEndian.Uint32(this.data[offset+4:]))
											this.Pairs[0] = int(binary.BigEndian.Uint32(this.data[offset:]))
											offset += 8 + this.Pairs[0]
											if this.Total >= offset+4 && string(data[offset:offset+4]) == "CLUS" {
												offset += 4
												this.Clusters[3] = int(data[offset])
												this.Clusters[2] = offset + 9
												this.Clusters[1] = int(binary.BigEndian.Uint32(this.data[offset+5:]))
												this.Clusters[0] = int(binary.BigEndian.Uint32(this.data[offset+1:]))
												offset += 9 + this.Clusters[0]
												if this.Total >= offset+4 && string(data[offset:offset+4]) == "MAPS" {
													offset += 4
													if this.Total >= offset+8 {
														this.Maps[2] = offset + 8
														this.Maps[1] = int(binary.BigEndian.Uint32(this.data[offset+4:]))
														this.Maps[0] = int(binary.BigEndian.Uint32(this.data[offset:]))
														offset += 8 + this.Maps[0]
														if this.Total >= offset+9 && string(data[offset:offset+4]) == "NODE" {
															offset += 4
															this.Nodes[3] = int(data[offset])
															this.Nodes[2] = offset + 9
															this.Nodes[1] = int(binary.BigEndian.Uint32(this.data[offset+5:]))
															this.Nodes[0] = int(binary.BigEndian.Uint32(this.data[offset+1:]))
															if offset+9+this.Nodes[0] != this.Total {
																this.Nodes[2] = 0
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
			this.Unlock()
			if this.Strings[2] == 0 || this.Numbers[2] == 0 || this.Pairs[2] == 0 || this.Clusters[2] == 0 || this.Maps[2] == 0 || this.Nodes[2] == 0 {
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
func (this *PrefixDB) rstring(index int) string {
	count, offset, width := this.Strings[1], this.Strings[2], this.Strings[3]
	if index >= count {
		return ""
	}
	start, end := rbytes(width, this.data[offset+(index*width):]), 0
	if index < count-1 {
		end = rbytes(width, this.data[offset+(index+1)*width:])
	} else {
		end = this.Strings[0] - (count * width)
	}
	return string(this.data[offset+(count*width)+start : offset+(count*width)+end])
}
func (this *PrefixDB) rnumber(index int) float64 {
	if index >= this.Numbers[1] {
		return 0.0
	}
	return math.Float64frombits(binary.BigEndian.Uint64(this.data[this.Numbers[2]+(index*8):]))
}
func (this *PrefixDB) rpair(index int, pairs map[string]interface{}) {
	if index < this.Pairs[1] {
		pair := binary.BigEndian.Uint64(this.data[this.Pairs[2]+(index*8):])
		if key := this.rstring(int((pair >> 32) & 0x0fffffff)); key != "" {
			switch (pair & 0xf0000000) >> 28 {
			case 1:
				pairs[key] = this.rstring(int(pair & 0x0fffffff))
			case 2:
				pairs[key] = this.rnumber(int(pair & 0x0fffffff))
			case 3:
				pairs[key] = true
			case 4:
				pairs[key] = false
			}
		}
	}
}
func (this *PrefixDB) rcluster(index int, pairs map[string]interface{}) {
	count, offset, width := this.Clusters[1], this.Clusters[2], this.Clusters[3]
	if index < count {
		start, end := rbytes(width, this.data[offset+(index*width):]), 0
		if index < count-1 {
			end = rbytes(width, this.data[offset+(index+1)*width:])
		} else {
			end = this.Clusters[0] - (count * width)
		}
		start += offset + (count * width)
		end += offset + (count * width)
		key := ""
		for start < end {
			section, index, size, _ := rpbits(this.data[start:])
			switch section {
			case 1:
				if key != "" {
					pairs[key] = this.rstring(index)
					key = ""
				} else {
					key = this.rstring(index)
				}
			case 2:
				if key != "" {
					pairs[key] = this.rnumber(index)
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
				this.rpair(index, pairs)
			}
			start += size
		}
	}
}
func (this *PrefixDB) Lookup(address net.IP, input map[string]interface{}) (output map[string]interface{}, err error) {
	output = input
	if this.data == nil || this.Total == 0 || this.Version == 0 || this.Strings[2] == 0 || this.Numbers[2] == 0 ||
		this.Pairs[2] == 0 || this.Clusters[2] == 0 || this.Maps[2] == 0 || this.Nodes[2] == 0 || address == nil {
		err = errors.New(`prefixdb: record not found`)
	} else {
		address = address.To16()
		offset := 0
		this.RLock()
		for bit := 0; bit < 128; bit++ {
			down := 0
			if (address[bit/8] & (1 << (7 - (byte(bit) % 8)))) != 0 {
				down = 1
			}
			offset = rnbits(this.Nodes[3], offset, down, this.data[this.Nodes[2]:])
			if offset == this.Nodes[1] || offset == 0 {
				break
			}
			if output == nil {
				output = map[string]interface{}{}
			}
			if offset > this.Nodes[1] {
				offset -= this.Nodes[1]
				if offset < this.Maps[0] {
					offset += this.Maps[2]
					key := ""
					for offset < this.Maps[2]+this.Maps[0] {
						section, index, size, last := rpbits(this.data[offset:])
						switch section {
						case 1:
							if key != "" {
								output[key] = this.rstring(index)
								key = ""
							} else {
								key = this.rstring(index)
							}
						case 2:
							if key != "" {
								output[key] = this.rnumber(index)
								key = ""
							}
						case 3:
							if key != "" {
								output[key] = true
								key = ""
							}
						case 4:
							if key != "" {
								output[key] = false
								key = ""
							}
						case 5:
							if key != "" {
								output[key] = nil
								key = ""
							}
						case 6:
							this.rpair(index, output)
						case 7:
							this.rcluster(index, output)
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
		this.RUnlock()
	}
	return output, err
}
