//go:build go1.24

package uhash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/zeebo/blake3"
)

func RandInt(in int) (out int) {
	if in <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(in)))
	if err != nil {
		return 0
	}

	return int(value.Int64())
}

func RandKey(size int, extra ...string) (out string, err error) {
	if size <= 0 || size > 256 {
		return "", errors.New("uhash: invalid size")
	}
	encoding := "hex"
	if len(extra) != 0 {
		encoding = strings.ToLower(extra[0])
	}

	value := make([]byte, size)
	rand.Read(value)
	switch encoding {
	case "std":
		out = base64.RawStdEncoding.EncodeToString(value)

	case "url":
		out = base64.RawURLEncoding.EncodeToString(value)

	default:
		out = hex.EncodeToString(value)
	}

	return
}

func Hash128(in []byte) (out [16]byte) {
	out = [16]byte{}

	hasher := blake3.New()
	hasher.Write(in)
	digest := hasher.Digest()
	hash := make([]byte, 16)
	digest.Read(hash)
	for index := 0; index < 16; index++ {
		out[index] = hash[index]
	}

	return
}

func Hash256(in []byte) (out [32]byte) {
	return sha256.Sum256(in)
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
