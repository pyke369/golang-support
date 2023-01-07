package chash

import (
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/pyke369/golang-support/uhash"
)

const (
	CHASH_MAGIC    uint32 = 0x48414843
	CHASH_REPLICAS uint8  = 128
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

type ByHash []item

func (a ByHash) Len() int           { return len(a) }
func (a ByHash) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByHash) Less(i, j int) bool { return a[i].hash < a[j].hash }

func (c *CHash) freeze() {
	c.Lock()
	if c.frozen {
		c.Unlock()
		return
	}
	c.ringSize = 0
	for _, tweight := range c.targets {
		c.ringSize += uint32(tweight) * uint32(c.replicas)
	}
	if c.ringSize == 0 {
		c.frozen = true
		c.Unlock()
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
				c.ring[offset] = item{uhash.Murmur2(key, -1), target}
				offset++
			}
		}
		target++
	}
	sort.Sort(ByHash(c.ring))
	c.frozen = true
	c.Unlock()
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

func (c *CHash) AddTarget(name string, weight uint8) bool {
	if weight > 0 && weight <= 100 && len(name) <= 128 && c.targets[name] != weight {
		c.Lock()
		c.targets[name] = weight
		c.frozen = false
		c.Unlock()
		return true
	}
	return false
}
func (c *CHash) RemoveTarget(name string) bool {
	c.Lock()
	delete(c.targets, name)
	c.frozen = false
	c.Unlock()
	return true
}
func (c *CHash) ClearTargets() bool {
	c.Lock()
	c.targets = make(map[string]uint8)
	c.frozen = false
	c.Unlock()
	return true
}

func (c *CHash) Serialize() []byte {
	c.freeze()
	c.RLock()
	size := uint32(4) + 4 + 1 + 2 + 4
	for _, name := range c.names {
		size += 1 + 1 + uint32(len(name))
	}
	size += (c.ringSize * 6)
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
	c.RUnlock()
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
	if magic != CHASH_MAGIC || size != uint32(len(serialized)) {
		return false
	}
	c.Lock()
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
		c.Unlock()
		return false
	}
	for item := uint32(0); item < ringSize && offset < size; item++ {
		c.ring[item].hash = uint32(serialized[offset]) + (uint32(serialized[offset+1]) << 8) + (uint32(serialized[offset+2]) << 16) + (uint32(serialized[offset+3]) << 24)
		c.ring[item].target = uint16(serialized[offset+4]) + (uint16(serialized[offset+5]) << 8)
		offset += 6
	}
	if offset != size {
		c.Unlock()
		return false
	}
	c.frozen = true
	c.Unlock()
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
	c.RLock()
	if count > len(c.targets) {
		count = len(c.targets)
	}
	if c.ringSize == 0 || count < 1 {
		c.RUnlock()
		return []string{}
	}
	hash := uhash.Murmur2([]byte(candidate), -1)
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
	c.RUnlock()
	return result
}
func (c *CHash) LookupBalance(candidate string, count int) string {
	result := c.Lookup(candidate, count)
	if len(result) > 0 {
		return result[rand.Intn(len(result))]
	}
	return ""
}
