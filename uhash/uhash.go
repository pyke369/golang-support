package uhash

func Murmur2(key []byte, keySize int) uint32 {
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
