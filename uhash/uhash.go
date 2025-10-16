package uhash

import (
	"crypto/rand"
	"encoding/binary"
)

func Rand(in int) (out int) {
	if in > 0 {
		value := make([]byte, 8)
		rand.Read(value)
		value[0] &= 0x7f
		out = int(binary.BigEndian.Uint64(value)) % in
	}

	return
}

func CRC16(inputs ...[]byte) uint16 {
	csum, size := uint64(0), 0
	if length := len(inputs); length > 0 {
		for index, input := range inputs {
			if index < length-1 && len(input)%2 != 0 {
				return 0
			}
			size += len(input)
			if size >= 64<<10 {
				return 0
			}
			for len(input) >= 32 {
				csum += uint64(uint32(input[3]) | uint32(input[2])<<8 | uint32(input[1])<<16 | uint32(input[0])<<24)
				csum += uint64(uint32(input[7]) | uint32(input[6])<<8 | uint32(input[5])<<16 | uint32(input[4])<<24)
				csum += uint64(uint32(input[11]) | uint32(input[10])<<8 | uint32(input[9])<<16 | uint32(input[8])<<24)
				csum += uint64(uint32(input[15]) | uint32(input[14])<<8 | uint32(input[13])<<16 | uint32(input[12])<<24)
				csum += uint64(uint32(input[19]) | uint32(input[18])<<8 | uint32(input[17])<<16 | uint32(input[16])<<24)
				csum += uint64(uint32(input[23]) | uint32(input[22])<<8 | uint32(input[21])<<16 | uint32(input[20])<<24)
				csum += uint64(uint32(input[27]) | uint32(input[26])<<8 | uint32(input[25])<<16 | uint32(input[24])<<24)
				csum += uint64(uint32(input[31]) | uint32(input[30])<<8 | uint32(input[29])<<16 | uint32(input[28])<<24)
				input = input[32:]
			}
			if len(input) >= 16 {
				csum += uint64(uint32(input[3]) | uint32(input[2])<<8 | uint32(input[1])<<16 | uint32(input[0])<<24)
				csum += uint64(uint32(input[7]) | uint32(input[6])<<8 | uint32(input[5])<<16 | uint32(input[4])<<24)
				csum += uint64(uint32(input[11]) | uint32(input[10])<<8 | uint32(input[9])<<16 | uint32(input[8])<<24)
				csum += uint64(uint32(input[15]) | uint32(input[14])<<8 | uint32(input[13])<<16 | uint32(input[12])<<24)
				input = input[16:]
			}
			if len(input) >= 8 {
				csum += uint64(uint32(input[3]) | uint32(input[2])<<8 | uint32(input[1])<<16 | uint32(input[0])<<24)
				csum += uint64(uint32(input[7]) | uint32(input[6])<<8 | uint32(input[5])<<16 | uint32(input[4])<<24)
				input = input[8:]
			}
			if len(input) >= 4 {
				csum += uint64(uint32(input[3]) | uint32(input[2])<<8 | uint32(input[1])<<16 | uint32(input[0])<<24)
				input = input[4:]
			}
			if len(input) >= 2 {
				csum += uint64(uint16(input[1]) | uint16(input[0])<<8)
				input = input[2:]
			}
			if len(input) >= 1 {
				csum += uint64(uint16(input[0]) << 8)
			}
		}
	}
	csum = (csum & 0xffff) + ((csum >> 16) & 0xffff) + ((csum >> 32) & 0xffff) + ((csum >> 48) & 0xffff)
	if csum > 0xffff {
		csum = (csum & 0xffff) + ((csum >> 16) & 0xffff) + ((csum >> 32) & 0xffff)
	}
	if csum > 0xffff {
		csum = (csum & 0xffff) + ((csum >> 16) & 0xffff)
	}

	return ^uint16(csum)
}
