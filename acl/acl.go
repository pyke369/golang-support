package acl

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
)

func init() {
	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
}

func CIDR(input string, values []string) (match bool) {
	if len(values) > 0 {
		remote := input
		if value, err := netip.ParseAddrPort(remote); err == nil {
			remote = value.Addr().String()
		}
		if remote, err := netip.ParseAddr(remote); err == nil {
			for _, value := range values {
				if network, err := netip.ParsePrefix(value); err == nil {
					if network.Contains(remote) {
						return true
					}
				}
			}
		}
		return false
	}
	return true
}
func CIDRConfig(input string, config *uconfig.UConfig, path string) bool {
	return CIDR(input, config.GetStrings(path))
}

// see https://akkadia.org/drepper/SHA-crypt.txt
var cryptb64 = base64.NewEncoding("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").WithPadding(base64.NoPadding)

func Crypt512(key, salt string, rounds int) (output string) {
	output = "$6$"
	if rounds == 0 {
		rounds = 5000
	}
	rounds = int(math.Max(1000, math.Min(999999999, float64(rounds))))
	if rounds != 5000 {
		output += fmt.Sprintf("rounds=%d$", rounds)
	}
	salt = salt[:int(math.Min(16, float64(len(salt))))]
	if salt == "" {
		value := make([]byte, 6)
		rand.Read(value)
		salt = cryptb64.EncodeToString(value)
	}
	output += salt + "$"

	// digest B (steps 4-8)
	bkey, bsalt, length := []byte(key), []byte(salt), len(key)
	hash := sha512.New() // 4
	hash.Write(bkey)     // 5
	hash.Write(bsalt)    // 6
	hash.Write(bkey)     // 7
	B := hash.Sum(nil)   // 8

	// digest A (steps 1-3 + 9-12)
	hash.Reset()                                 // 1
	hash.Write(bkey)                             // 2
	hash.Write(bsalt)                            // 3
	for index := 0; index < length/64; index++ { // 9
		hash.Write(B)
	}
	if remaining := length % 64; remaining != 0 { // 10
		hash.Write(B[:remaining])
	}
	for bit := length; bit > 0; bit >>= 1 { // 11
		if bit%2 == 0 {
			hash.Write(bkey)
		} else {
			hash.Write(B)
		}
	}
	A := hash.Sum(nil) // 12

	// digest DP (steps 13-15)
	hash.Reset()                              // 13
	for index := 0; index < length; index++ { // 14
		hash.Write(bkey)
	}
	DP := hash.Sum(nil) // 15

	// sequence P (step 16)
	P := []byte{}
	for index := 0; index < length/64; index++ { // 16a
		P = append(P, DP...)
	}
	if remaining := length % 64; remaining != 0 { // 16b
		P = append(P, DP[:remaining]...)
	}

	// digest DS (steps 17-19)
	hash.Reset()                                    // 17
	for index := 0; index < 16+int(A[0]); index++ { // 18
		hash.Write(bsalt)
	}
	DS := hash.Sum(nil) // 19

	// sequence S (step 20)
	S := []byte{}
	length = len(salt)
	for index := 0; index < length/64; index++ { // 20a
		S = append(S, DS...)
	}
	if remaining := length % 64; remaining != 0 { // 20b
		S = append(S, DS[:remaining]...)
	}

	// digest C (step 21)
	for index := 0; index < rounds; index++ {
		hash.Reset() // 21a
		if index%2 != 0 {
			hash.Write(P) // 21b
		} else {
			hash.Write(A) // 21c
		}
		if index%3 != 0 {
			hash.Write(S) // 21d
		}
		if index%7 != 0 {
			hash.Write(P) // 21e
		}
		if index%2 != 0 {
			hash.Write(A) // 21f
		} else {
			hash.Write(P) // 21g
		}
		copy(A, hash.Sum(nil)) // 21h
	}

	// digest C special base64 encoding
	C := []byte(cryptb64.EncodeToString([]byte{
		A[0], A[21], A[42], A[22], A[43], A[1], A[44], A[2], A[23], A[3], A[24], A[45], A[25], A[46], A[4], A[47],
		A[5], A[26], A[6], A[27], A[48], A[28], A[49], A[7], A[50], A[8], A[29], A[9], A[30], A[51], A[31], A[52],
		A[10], A[53], A[11], A[32], A[12], A[33], A[54], A[34], A[55], A[13], A[56], A[14], A[35], A[15], A[36], A[57],
		A[37], A[58], A[16], A[59], A[17], A[38], A[18], A[39], A[60], A[40], A[61], A[19], A[62], A[20], A[41], 0, 0, A[63],
	}))
	for index := 0; index < len(C); index += 4 {
		C[index], C[index+3] = C[index+3], C[index]
		C[index+1], C[index+2] = C[index+2], C[index+1]
	}
	return output + string(C[:86])
}

func Password(input string, values []string) bool {
	login, password := "", strings.TrimSpace(input)
	if parts := strings.Split(input, ":"); len(parts) >= 2 {
		login, password = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	for _, value := range values {
		check := strings.TrimSpace(value)
		if len(check) > 1 && check[0] == '@' {
			if PasswordFile(input, strings.TrimSpace(check[1:])) {
				return true
			}
		} else {
			if login != "" {
				if parts := strings.Split(value, ":"); len(parts) < 2 || login != strings.TrimSpace(parts[0]) {
					continue
				} else {
					check = strings.TrimSpace(parts[1])
				}
			}
			if parts := strings.Split(check, "$"); len(parts) >= 4 && parts[0] == "" && parts[1] == "6" && parts[2] != "" && parts[3] != "" {
				rounds, salt := 5000, parts[2]
				if len(parts) > 4 && strings.HasPrefix(parts[2], "rounds=") {
					rounds, _ = strconv.Atoi(parts[2][7:])
					salt = parts[3]
				}
				if Crypt512(password, salt, rounds) == check {
					return true
				}
			} else if password == check {
				return true
			}
		}
	}
	return false
}
func PasswordConfig(input string, config *uconfig.UConfig, path string) bool {
	return Password(input, config.GetStrings(path))
}
func PasswordFile(input, path string) bool {
	lines := []string{}
	if content, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if (len(line) >= 1 && line[0] != '#') || (len(line) >= 2 && line[0] != '/' && line[1] != '/') {
				lines = append(lines, line)
			}
		}
	}
	return Password(input, lines)
}

type RANGE struct {
	dates [2]time.Time
	days  [2]int
	times [2]int
}

func Ranges(input time.Time, values []string) (match bool) {
	if len(values) > 0 {
		ranges, matcher1, matcher2, matcher3, days := []RANGE{},
			rcache.Get(`^(\d{4}-\d{2}-\d{2})?-(\d{4}-\d{2}-\d{2})?$`),
			rcache.Get(`^(mon|tue|wed|thu|fri|sat|sun)?-(mon|tue|wed|thu|fri|sat|sun)?$`),
			rcache.Get(`^(?:(\d{2}):(\d{2})(?::(\d{2}))?)?-(?:(\d{2}):(\d{2})(?::(\d{2}))?)?$`),
			map[string]int{"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
		for _, path := range values {
			entry := RANGE{}
			for _, value := range strings.Split(path, " ") {
				if captures := matcher1.FindStringSubmatch(value); len(captures) == 3 {
					if value, err := time.Parse("2006-01-02", captures[1]); err == nil {
						entry.dates[0] = value
					}
					if value, err := time.Parse("2006-01-02", captures[2]); err == nil {
						entry.dates[1] = value.Add(86399 * time.Second)
					}
				} else if captures := matcher2.FindStringSubmatch(strings.ToLower(value)); len(captures) == 3 {
					entry.days[0], entry.days[1] = days[captures[1]], days[captures[2]]
				} else if captures := matcher3.FindStringSubmatch(value); len(captures) == 7 {
					hour, _ := strconv.ParseInt(captures[1], 10, 64)
					minute, _ := strconv.ParseInt(captures[2], 10, 64)
					second, _ := strconv.ParseInt(captures[3], 10, 64)
					entry.times[0] = int(hour)*3600 + int(minute)*60 + int(second)
					hour, _ = strconv.ParseInt(captures[4], 10, 64)
					minute, _ = strconv.ParseInt(captures[5], 10, 64)
					second, _ = strconv.ParseInt(captures[6], 10, 64)
					entry.times[1] = int(hour)*3600 + int(minute)*60 + int(second)
				}
			}
			ranges = append(ranges, entry)
		}
		now := input.UTC()
		day, stamp := int(now.Weekday()), now.Hour()*3600+now.Minute()*60+now.Second()
		if day == 0 {
			day = 7
		}
		for _, entry := range ranges {
			if (!entry.dates[0].IsZero() && now.Sub(entry.dates[0]) < 0) || (!entry.dates[1].IsZero() && now.Sub(entry.dates[1]) > 0) ||
				(entry.days[0] != 0 && day < entry.days[0]) || (entry.days[1] != 0 && day > entry.days[1]) ||
				(entry.times[0] != 0 && stamp < entry.times[0]) || (entry.times[1] != 0 && stamp > entry.times[1]) {
				continue
			}
			return true
		}
		return false
	}
	return true
}
func RangesConfig(input time.Time, config *uconfig.UConfig, path string) bool {
	return Ranges(input, config.GetStrings(path))
}
