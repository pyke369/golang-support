package chash

import (
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	CHASH_MAGIC    uint32 = 0x48414843
	CHASH_REPLICAS        = 128
)

type item struct {
	hash   uint32
	target uint16
}

type CHash struct {
	targets  map[string]uint8
	names    []string
	ring     []item
	ringSize uint32
	replicas uint8
	frozen   bool
	sync.RWMutex
}

func init() {
	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
}

func mmhash2(key []byte, keySize int) uint32 {
	var magic, hash, current, value uint32 = 0x5bd1e995, uint32(0x4d4d4832 ^ keySize), 0, 0

	if keySize < 0 {
		keySize = len(key)
	}
	for keySize >= 4 {
		value = uint32(key[current]) | uint32(key[current+1])<<8 |
			uint32(key[current+2])<<16 | uint32(key[current+3])<<24
		value *= magic
		value ^= value >> 24
		value *= magic
		hash *= magic
		hash ^= value
		current += 4
		keySize -= 4
	}
	if keySize >= 3 {
		hash ^= uint32(key[current+2]) << 16
	}
	if keySize >= 2 {
		hash ^= uint32(key[current+1]) << 8
	}
	if keySize >= 1 {
		hash ^= uint32(key[current])
	}
	if keySize != 0 {
		hash *= magic
	}
	hash ^= hash >> 13
	hash *= magic
	hash ^= hash >> 15
	return hash
}

type ByHash []item

func (a ByHash) Len() int           { return len(a) }
func (a ByHash) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByHash) Less(i, j int) bool { return a[i].hash < a[j].hash }

func (this *CHash) freeze() {
	this.Lock()
	defer this.Unlock()
	if this.frozen {
		return
	}
	this.ringSize = 0
	for _, tweight := range this.targets {
		this.ringSize += uint32(tweight) * uint32(this.replicas)
	}
	if this.ringSize == 0 {
		this.frozen = true
		return
	}

	var (
		target uint16 = 0
		offset uint32 = 0
		key    []byte = make([]byte, 128)
	)
	this.names = make([]string, len(this.targets))
	this.ring = make([]item, this.ringSize)
	for tname, tweight := range this.targets {
		this.names[target] = tname
		for weight := uint8(0); weight < tweight; weight++ {
			for replica := uint8(0); replica < this.replicas; replica++ {
				key = append(key[:0], tname...)
				key = strconv.AppendInt(key, int64(weight), 10)
				key = strconv.AppendInt(key, int64(replica), 10)
				this.ring[offset] = item{mmhash2(key, -1), target}
				offset++
			}
		}
		target++
	}
	sort.Sort(ByHash(this.ring))
	this.frozen = true
}

func New(replicas ...uint8) *CHash {
	chash := &CHash{
		targets:  make(map[string]uint8),
		names:    nil,
		ring:     nil,
		ringSize: 0,
		replicas: CHASH_REPLICAS,
		frozen:   false,
	}
	if len(replicas) > 0 {
		chash.replicas = replicas[0]
	}
	if chash.replicas < 1 {
		chash.replicas = 1
	}
	if chash.replicas > CHASH_REPLICAS {
		chash.replicas = CHASH_REPLICAS
	}
	return chash
}

func (this *CHash) AddTarget(name string, weight uint8) bool {
	if weight > 0 && weight <= 100 && len(name) <= 128 && this.targets[name] != weight {
		this.Lock()
		defer this.Unlock()
		this.targets[name] = weight
		this.frozen = false
		return true
	}
	return false
}
func (this *CHash) RemoveTarget(name string) bool {
	this.Lock()
	defer this.Unlock()
	delete(this.targets, name)
	this.frozen = false
	return true
}
func (this *CHash) ClearTargets() bool {
	this.Lock()
	defer this.Unlock()
	this.targets = make(map[string]uint8)
	this.frozen = false
	return true
}

func (this *CHash) Serialize() []byte {
	this.freeze()
	this.RLock()
	defer this.RUnlock()
	size := uint32(4) + 4 + 1 + 2 + 4
	for _, name := range this.names {
		size += 1 + 1 + uint32(len(name))
	}
	size += (this.ringSize * 6)
	serialized := make([]byte, size)
	offset := uint32(0)
	serialized[offset] = byte(CHASH_MAGIC & 0xff)
	serialized[offset+1] = byte((CHASH_MAGIC >> 8) & 0xff)
	serialized[offset+2] = byte((CHASH_MAGIC >> 16) & 0xff)
	serialized[offset+3] = byte((CHASH_MAGIC >> 24) & 0xff)
	serialized[offset+4] = byte(size & 0xff)
	serialized[offset+5] = byte((size >> 8) & 0xff)
	serialized[offset+6] = byte((size >> 16) & 0xff)
	serialized[offset+7] = byte((size >> 24) & 0xff)
	serialized[offset+8] = this.replicas
	serialized[offset+9] = byte(uint16(len(this.names)) & 0xff)
	serialized[offset+10] = byte(((uint16(len(this.names))) >> 8) & 0xff)
	serialized[offset+11] = byte(this.ringSize & 0xff)
	serialized[offset+12] = byte((this.ringSize >> 8) & 0xff)
	serialized[offset+13] = byte((this.ringSize >> 16) & 0xff)
	serialized[offset+14] = byte((this.ringSize >> 24) & 0xff)
	offset += 15
	for _, name := range this.names {
		serialized[offset] = this.targets[name]
		serialized[offset+1] = byte(len(name) & 0xff)
		copy(serialized[offset+2:offset+2+uint32(serialized[offset+1])], []byte(name))
		offset += 2 + uint32(serialized[offset+1])
	}
	for _, item := range this.ring {
		serialized[offset] = byte(item.hash & 0xff)
		serialized[offset+1] = byte((item.hash >> 8) & 0xff)
		serialized[offset+2] = byte((item.hash >> 16) & 0xff)
		serialized[offset+3] = byte((item.hash >> 24) & 0xff)
		serialized[offset+4] = byte(item.target & 0xff)
		serialized[offset+5] = byte((item.target >> 8) & 0xff)
		offset += 6
	}
	return serialized
}
func (this *CHash) FileSerialize(path string) bool {
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return false
	}
	defer handle.Close()
	if _, err := handle.Write(this.Serialize()); err != nil {
		return false
	}
	return true
}

func (this *CHash) Unserialize(serialized []byte) bool {
	this.Lock()
	defer this.Unlock()
	if len(serialized) < 15 {
		return false
	}
	magic := uint32(serialized[0]) + (uint32(serialized[1]) << 8) + (uint32(serialized[2]) << 16) + (uint32(serialized[3]) << 24)
	size := uint32(serialized[4]) + (uint32(serialized[5]) << 8) + (uint32(serialized[6]) << 16) + (uint32(serialized[7]) << 24)
	replicas := serialized[8]
	names := uint16(serialized[9]) + (uint16(serialized[10]) << 8)
	ringSize := uint32(serialized[11]) + (uint32(serialized[12]) << 8) + (uint32(serialized[13]) << 16) + (uint32(serialized[14]) << 24)
	if magic != CHASH_MAGIC || size != uint32(len(serialized)) {
		return false
	}
	this.targets = make(map[string]uint8)
	this.names = make([]string, names)
	this.ring = make([]item, ringSize)
	this.ringSize = ringSize
	this.replicas = replicas
	offset := uint32(15)
	for index := uint16(0); index < names && offset < size; index++ {
		len := uint32(serialized[offset+1])
		this.names[index] = string(serialized[offset+2 : offset+2+len])
		this.targets[this.names[index]] = serialized[offset]
		offset += 2 + len
	}
	if offset > size {
		return false
	}
	for item := uint32(0); item < ringSize && offset < size; item++ {
		this.ring[item].hash = uint32(serialized[offset]) + (uint32(serialized[offset+1]) << 8) + (uint32(serialized[offset+2]) << 16) + (uint32(serialized[offset+3]) << 24)
		this.ring[item].target = uint16(serialized[offset+4]) + (uint16(serialized[offset+5]) << 8)
		offset += 6
	}
	if offset != size {
		return false
	}
	this.frozen = true
	return true
}
func (this *CHash) FileUnserialize(path string) bool {
	handle, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return false
	}
	if info.Size() > 128*1024*1024 {
		return false
	}
	serialized := make([]byte, info.Size())
	read, err := handle.Read(serialized)
	if int64(read) != info.Size() || err != nil {
		return false
	}
	return this.Unserialize(serialized)
}

func (this *CHash) Lookup(candidate string, count int) []string {
	var start uint32 = 0

	this.freeze()
	this.RLock()
	defer this.RUnlock()
	if count > len(this.targets) {
		count = len(this.targets)
	}
	if this.ringSize == 0 || count < 1 {
		return []string{}
	}
	hash := mmhash2([]byte(candidate), -1)
	if hash > this.ring[0].hash && hash <= this.ring[this.ringSize-1].hash {
		start = this.ringSize / 2
		span := start / 2
		for {
			if hash > this.ring[start].hash && hash <= this.ring[start+1].hash {
				break
			}
			if hash > this.ring[start].hash {
				start += span
			} else {
				start -= span
			}
			span /= 2
			if span < 1 {
				span = 1
			}
		}
	}
	result := make([]string, count)
	rank := 0
	for rank < count {
		index := 0
		for index = 0; index < rank; index++ {
			if result[index] == this.names[this.ring[start].target] {
				break
			}
		}
		if index >= rank {
			result[rank] = this.names[this.ring[start].target]
			rank++
		}
		start++
		if start >= this.ringSize {
			start = 0
		}
	}
	return result
}
func (this *CHash) LookupBalance(candidate string, count int) string {
	result := this.Lookup(candidate, count)
	if len(result) > 0 {
		return result[rand.Intn(len(result))]
	}
	return ""
}
