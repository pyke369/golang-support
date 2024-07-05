package chash

import (
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
)

const (
	chashMagic    uint32 = 0x48414843
	chashReplicas uint8  = 128
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
	mu       sync.RWMutex
}

type ByHash []item

func (a ByHash) Len() int           { return len(a) }
func (a ByHash) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByHash) Less(i, j int) bool { return a[i].hash < a[j].hash }

func murmur2(key []byte, keySize int) uint32 {
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

func (c *CHash) freeze() {
	c.mu.Lock()
	if c.frozen {
		c.mu.Unlock()
		return
	}
	c.ringSize = 0
	for _, tweight := range c.targets {
		c.ringSize += uint32(tweight) * uint32(c.replicas)
	}
	if c.ringSize == 0 {
		c.frozen = true
		c.mu.Unlock()
		return
	}

	var (
		target uint16 = 0
		offset uint32 = 0
		key    []byte = make([]byte, 128)
	)
	c.names = make([]string, len(c.targets))
	c.ring = make([]item, c.ringSize)
	for tname, tweight := range c.targets {
		c.names[target] = tname
		for weight := uint8(0); weight < tweight; weight++ {
			for replica := uint8(0); replica < c.replicas; replica++ {
				key = append(key[:0], tname...)
				key = strconv.AppendInt(key, int64(weight), 10)
				key = strconv.AppendInt(key, int64(replica), 10)
				c.ring[offset] = item{murmur2(key, -1), target}
				offset++
			}
		}
		target++
	}
	sort.Sort(ByHash(c.ring))
	c.frozen = true
	c.mu.Unlock()
}

func New(in ...uint8) *CHash {
	chash := &CHash{
		targets:  make(map[string]uint8),
		names:    nil,
		ring:     nil,
		ringSize: 0,
		replicas: chashReplicas,
		frozen:   false,
	}
	if len(in) > 0 {
		chash.replicas = in[0]
	}
	chash.replicas = min(chashReplicas, max(1, chash.replicas))
	return chash
}

func (c *CHash) AddTarget(name string, weight uint8) bool {
	if weight > 0 && weight <= 100 && len(name) <= 128 && c.targets[name] != weight {
		c.mu.Lock()
		c.targets[name] = weight
		c.frozen = false
		c.mu.Unlock()
		return true
	}
	return false
}
func (c *CHash) RemoveTarget(name string) bool {
	c.mu.Lock()
	delete(c.targets, name)
	c.frozen = false
	c.mu.Unlock()
	return true
}
func (c *CHash) ClearTargets() bool {
	c.mu.Lock()
	c.targets = make(map[string]uint8)
	c.frozen = false
	c.mu.Unlock()
	return true
}

func (c *CHash) Serialize() []byte {
	c.freeze()
	c.mu.RLock()
	size := uint32(4) + 4 + 1 + 2 + 4
	for _, name := range c.names {
		size += 1 + 1 + uint32(len(name))
	}
	size += (c.ringSize * 6)
	serialized := make([]byte, size)
	offset := uint32(0)
	serialized[offset] = byte(chashMagic & 0xff)
	serialized[offset+1] = byte((chashMagic >> 8) & 0xff)
	serialized[offset+2] = byte((chashMagic >> 16) & 0xff)
	serialized[offset+3] = byte((chashMagic >> 24) & 0xff)
	serialized[offset+4] = byte(size & 0xff)
	serialized[offset+5] = byte((size >> 8) & 0xff)
	serialized[offset+6] = byte((size >> 16) & 0xff)
	serialized[offset+7] = byte((size >> 24) & 0xff)
	serialized[offset+8] = c.replicas
	serialized[offset+9] = byte(uint16(len(c.names)) & 0xff)
	serialized[offset+10] = byte(((uint16(len(c.names))) >> 8) & 0xff)
	serialized[offset+11] = byte(c.ringSize & 0xff)
	serialized[offset+12] = byte((c.ringSize >> 8) & 0xff)
	serialized[offset+13] = byte((c.ringSize >> 16) & 0xff)
	serialized[offset+14] = byte((c.ringSize >> 24) & 0xff)
	offset += 15
	for _, name := range c.names {
		serialized[offset] = c.targets[name]
		serialized[offset+1] = byte(len(name) & 0xff)
		copy(serialized[offset+2:offset+2+uint32(serialized[offset+1])], []byte(name))
		offset += 2 + uint32(serialized[offset+1])
	}
	for _, item := range c.ring {
		serialized[offset] = byte(item.hash & 0xff)
		serialized[offset+1] = byte((item.hash >> 8) & 0xff)
		serialized[offset+2] = byte((item.hash >> 16) & 0xff)
		serialized[offset+3] = byte((item.hash >> 24) & 0xff)
		serialized[offset+4] = byte(item.target & 0xff)
		serialized[offset+5] = byte((item.target >> 8) & 0xff)
		offset += 6
	}
	c.mu.RUnlock()
	return serialized
}
func (c *CHash) FileSerialize(path string) bool {
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return false
	}
	if _, err := handle.Write(c.Serialize()); err != nil {
		handle.Close()
		return false
	}
	handle.Close()
	return true
}

func (c *CHash) Unserialize(serialized []byte) bool {
	if len(serialized) < 15 {
		return false
	}
	magic := uint32(serialized[0]) + (uint32(serialized[1]) << 8) + (uint32(serialized[2]) << 16) + (uint32(serialized[3]) << 24)
	size := uint32(serialized[4]) + (uint32(serialized[5]) << 8) + (uint32(serialized[6]) << 16) + (uint32(serialized[7]) << 24)
	replicas := serialized[8]
	names := uint16(serialized[9]) + (uint16(serialized[10]) << 8)
	ringSize := uint32(serialized[11]) + (uint32(serialized[12]) << 8) + (uint32(serialized[13]) << 16) + (uint32(serialized[14]) << 24)
	if magic != chashMagic || size != uint32(len(serialized)) {
		return false
	}
	c.mu.Lock()
	c.targets = make(map[string]uint8)
	c.names = make([]string, names)
	c.ring = make([]item, ringSize)
	c.ringSize = ringSize
	c.replicas = replicas
	offset := uint32(15)
	for index := uint16(0); index < names && offset < size; index++ {
		length := uint32(serialized[offset+1])
		c.names[index] = string(serialized[offset+2 : offset+2+length])
		c.targets[c.names[index]] = serialized[offset]
		offset += 2 + length
	}
	if offset > size {
		c.mu.Unlock()
		return false
	}
	for item := uint32(0); item < ringSize && offset < size; item++ {
		c.ring[item].hash = uint32(serialized[offset]) + (uint32(serialized[offset+1]) << 8) + (uint32(serialized[offset+2]) << 16) + (uint32(serialized[offset+3]) << 24)
		c.ring[item].target = uint16(serialized[offset+4]) + (uint16(serialized[offset+5]) << 8)
		offset += 6
	}
	if offset != size {
		c.mu.Unlock()
		return false
	}
	c.frozen = true
	c.mu.Unlock()
	return true
}
func (c *CHash) FileUnserialize(path string) bool {
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
	return c.Unserialize(serialized)
}

func (c *CHash) Lookup(candidate string, count int) []string {
	var start uint32 = 0

	c.freeze()
	c.mu.RLock()
	if count > len(c.targets) {
		count = len(c.targets)
	}
	if c.ringSize == 0 || count < 1 {
		c.mu.RUnlock()
		return []string{}
	}
	hash := murmur2([]byte(candidate), -1)
	if hash > c.ring[0].hash && hash <= c.ring[c.ringSize-1].hash {
		start = c.ringSize / 2
		span := start / 2
		for {
			if hash > c.ring[start].hash && hash <= c.ring[start+1].hash {
				break
			}
			if hash > c.ring[start].hash {
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
	result, rank := make([]string, count), 0
	for rank < count {
		index := 0
		for index = 0; index < rank; index++ {
			if result[index] == c.names[c.ring[start].target] {
				break
			}
		}
		if index >= rank {
			result[rank] = c.names[c.ring[start].target]
			rank++
		}
		start++
		if start >= c.ringSize {
			start = 0
		}
	}
	c.mu.RUnlock()
	return result
}
func (c *CHash) LookupBalance(candidate string, count int) string {
	result := c.Lookup(candidate, count)
	if len(result) > 0 {
		return result[rand.Intn(len(result))]
	}
	return ""
}
