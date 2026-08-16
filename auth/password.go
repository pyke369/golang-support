//go:build go1.24

package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/file"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ustr"
	a2 "golang.org/x/crypto/argon2"
	bc "golang.org/x/crypto/bcrypt"
)

var (
	sets = []string{
		`abcdefghijklmnopqrstuvwxyz`,
		`ABCDEFGHIJKLMNOPQRSTUVWXYZ`,
		`0123456789`,
		` ,-._`,
		`!$&*@`,
		`"#%'()+/:;<=>?[\]^` + "`" + `{|}~`,
	}
	seqs = [][]rune{
		[]rune("abcdefghijklmnopqrstuvwxyz"),
		[]rune("01234567890"),
		[]rune("qwertyuiop"),
		[]rune("asdfghjkl"),
		[]rune("zxcvbnm"),
		[]rune("azertyuiop"),
		[]rune("qsdfghjklm"),
		[]rune("wxcvbn"),
	}

	// see https://akkadia.org/drepper/SHA-crypt.txt
	cryptMatcher = regexp.MustCompile(`^[./0-9A-Za-z]{8,22}$`)
	cryptBase64  = base64.NewEncoding("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").WithPadding(base64.NoPadding)
)

func init() {
	count := len(seqs)
	for index := 0; index < count; index++ {
		seqs = append(seqs, []rune(ustr.Reverse(string(seqs[index]))))
	}
}

func crypt512(in, salt string, rounds int) (out string, err error) {
	if len(in) > 128 {
		return "", errors.New("auth: password is too long")
	}
	if rounds <= 0 {
		return "", errors.New("auth: invalid rounds parameter")
	}
	rounds = min(999999999, max(1000, rounds))

	salt = strings.TrimSpace(salt)
	if salt == "" {
		value := make([]byte, 12)
		rand.Read(value)
		salt = cryptBase64.EncodeToString(value)

	} else if !cryptMatcher.MatchString(salt) || len(salt) > 16 {
		return "", errors.New("auth: invalid salt")
	}
	out = "$6$"
	if rounds != 5000 {
		out += "rounds=" + strconv.Itoa(rounds) + "$"
	}
	out += salt + "$"

	// digest B (steps 4-8)
	key, bsalt, length := []byte(in), []byte(salt), len(in)
	hash := sha512.New() // 4
	hash.Write(key)      // 5
	hash.Write(bsalt)    // 6
	hash.Write(key)      // 7
	B := hash.Sum(nil)   // 8

	// digest A (steps 1-3 + 9-12)
	hash.Reset()                                 // 1
	hash.Write(key)                              // 2
	hash.Write(bsalt)                            // 3
	for index := 0; index < length/64; index++ { // 9
		hash.Write(B)
	}
	if remaining := length % 64; remaining != 0 { // 10
		hash.Write(B[:remaining])
	}
	for bit := length; bit > 0; bit >>= 1 { // 11
		if bit%2 == 0 {
			hash.Write(key)

		} else {
			hash.Write(B)
		}
	}
	A := hash.Sum(nil) // 12

	// digest DP (steps 13-15)
	hash.Reset()                              // 13
	for index := 0; index < length; index++ { // 14
		hash.Write(key)
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
	C := []byte(cryptBase64.EncodeToString([]byte{
		A[0], A[21], A[42], A[22], A[43], A[1], A[44], A[2], A[23], A[3], A[24], A[45], A[25], A[46], A[4], A[47],
		A[5], A[26], A[6], A[27], A[48], A[28], A[49], A[7], A[50], A[8], A[29], A[9], A[30], A[51], A[31], A[52],
		A[10], A[53], A[11], A[32], A[12], A[33], A[54], A[34], A[55], A[13], A[56], A[14], A[35], A[15], A[36], A[57],
		A[37], A[58], A[16], A[59], A[17], A[38], A[18], A[39], A[60], A[40], A[61], A[19], A[62], A[20], A[41], 0, 0, A[63],
	}))
	for index := 0; index < len(C); index += 4 {
		C[index], C[index+3] = C[index+3], C[index]
		C[index+1], C[index+2] = C[index+2], C[index+1]
	}
	return out + string(C[:86]), nil
}

func Crypt512(in, salt string) (out string, err error) {
	return crypt512(in, salt, 100000)
}

func bcrypt(in string, cost int) (out string, err error) {
	if len(in) > 72 {
		return "", errors.New("auth: password is too long")
	}
	if cost <= 0 {
		return "", errors.New("auth: invalid cost parameter")
	}
	cost = min(15, max(4, cost))

	value, err := bc.GenerateFromPassword([]byte(in), cost)
	if err != nil {
		return "", err
	}

	return string(value), nil
}

func Bcrypt(in string) (out string, err error) {
	return bcrypt(in, 12)
}

func argon2(in, salt string, memory, time, threads int) (out string, err error) {
	if len(in) > 128 {
		return "", errors.New("auth: password is too long")
	}
	if memory <= 0 {
		return "", errors.New("auth: invalid memory parameter")
	}
	if time <= 0 {
		return "", errors.New("auth: invalid time parameter")
	}
	if threads <= 0 {
		return "", errors.New("auth: invalid threads parameter")
	}
	memory = min(256<<10, max(8<<10, memory))
	time = min(8, max(1, time))
	threads = min(4, max(1, threads))

	var bsalt []byte

	salt = strings.TrimSpace(salt)
	if salt == "" {
		bsalt = make([]byte, 16)
		rand.Read(bsalt)
		salt = base64.RawStdEncoding.EncodeToString(bsalt)

	} else {
		value, err := base64.RawStdEncoding.DecodeString(salt)
		if err != nil || len(value) < 8 || len(value) > 16 {
			return "", errors.New("auth: invalid salt")
		}
		bsalt = value
	}

	return "$argon2id$v=19" + "$m=" + strconv.Itoa(memory) + ",t=" + strconv.Itoa(time) + ",p=" + strconv.Itoa(threads) + "$" + salt +
		"$" + base64.RawStdEncoding.EncodeToString(a2.IDKey([]byte(in), bsalt, uint32(time), uint32(memory), uint8(threads), 32)), nil
}

func Argon2(in, salt string) (out string, err error) {
	return argon2(in, salt, 19<<10, 2, 1)
}

func Password(in string, values []string) (pass bool, entry string) {
	if len(values) == 0 {
		return false, ""
	}

	parts := strings.SplitN(in, ":", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false, ""
	}
	login, password := strings.TrimSpace(parts[0]), parts[1]

	defer func(start time.Time) {
		if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
			time.Sleep(200*time.Millisecond - elapsed)
		}
	}(time.Now())

	if login == parts[0] {
		for _, value := range values {
			parts := strings.Split(value, ":")
			if len(parts) < 2 || subtle.ConstantTimeCompare([]byte(login), []byte(strings.TrimSpace(parts[0]))) == 0 {
				continue
			}
			check := strings.TrimSpace(parts[1])
			if check == "" || check[0] == '!' || check[0] == '*' {
				continue
			}
			parts[1] = "*"
			entry = strings.Join(parts, ":")

			if parts := strings.Split(check, "$"); len(parts) >= 4 && parts[0] == "" && parts[2] != "" && parts[3] != "" {
				switch parts[1] {
				case "6":
					rounds, salt := 5000, parts[2]
					if len(parts) > 4 && strings.HasPrefix(parts[2], "rounds=") {
						if value, err := strconv.Atoi(parts[2][7:]); err == nil {
							rounds = value
							if rounds < 100000 || rounds > 1000000 {
								continue
							}
						}
						salt = parts[3]
					}
					if encrypted, err := crypt512(password, salt, rounds); err == nil {
						if subtle.ConstantTimeCompare([]byte(encrypted), []byte(check)) == 1 {
							return true, entry
						}
					}

				case "2a", "2b":
					if cost, err := bc.Cost([]byte(check)); err == nil && cost <= 15 {
						if bc.CompareHashAndPassword([]byte(check), []byte(password)) == nil {
							return true, entry
						}
					}

				case "argon2id":
					if len(parts) != 6 || parts[2] != "v=19" || parts[4] == "" || parts[5] == "" {
						continue
					}
					memory, time, threads := 0, 0, 0
					for _, part := range strings.Split(parts[3], ",") {
						part = strings.TrimSpace(part)
						switch {
						case strings.HasPrefix(part, "m="):
							if value, err := strconv.Atoi(strings.TrimPrefix(part, "m=")); err == nil {
								memory = value
							}

						case strings.HasPrefix(part, "t="):
							if value, err := strconv.Atoi(strings.TrimPrefix(part, "t=")); err == nil {
								time = value
							}

						case strings.HasPrefix(part, "p="):
							if value, err := strconv.Atoi(strings.TrimPrefix(part, "p=")); err == nil {
								threads = value
							}
						}
					}

					if memory <= 256<<10 && time <= 8 && threads <= 4 {
						if encrypted, err := argon2(password, parts[4], memory, time, threads); err == nil {
							if subtle.ConstantTimeCompare([]byte(encrypted), []byte(check)) == 1 {
								return true, entry
							}
						}
					}
				}
			}
		}
	}

	return false, ""
}

func PasswordConfig(in string, config *uconfig.UConfig, path string) (pass bool, entry string) {
	return Password(in, config.Strings(path))
}

func PasswordFile(in, path string) (pass bool, entry string) {
	lines, err := file.Read(path, map[string]any{"options": "empty comment trim"})
	if err != nil {
		return false, ""
	}

	return Password(in, lines)
}

func passwordContains(runes, seq []rune, start int) (offset, length int) {
	for start < len(runes)-2 {
		sindex := 0
		for sindex < len(seq) {
			if seq[sindex] == runes[start] {
				break
			}
			sindex++
		}
		if sindex < len(seq) {
			matched, rindex := 1, start+1
			sindex++
			for rindex < len(runes) && sindex < len(seq) {
				if seq[sindex] == runes[rindex] {
					matched++

				} else {
					break
				}
				rindex++
				sindex++
			}
			if matched > 2 {
				return start, matched
			}
		}
		start++
	}

	return
}

func passwordPrune(runes, seq []rune) []rune {
	start := 0
	for {
		offset, length := passwordContains(runes, seq, start)
		if length < 3 {
			break
		}
		copy(runes[offset+2:], runes[offset+length:])
		runes = runes[:len(runes)-(length-2)]
		start = offset
	}

	return runes
}

func PasswordEntropy(in string, extra ...[]string) (entropy float64, pass bool) {
	pool, chars, contains := 0, map[rune]struct{}{}, make([]bool, len(sets))
	for _, char := range in {
		chars[char] = struct{}{}
	}
	for char := range chars {
		match := false
		for set := 0; set < len(sets); set++ {
			if strings.ContainsRune(sets[set], char) {
				contains[set], match = true, true
				break
			}
		}
		if !match {
			pool++
		}
	}
	for set, contain := range contains {
		if contain {
			pool += len(sets[set])
		}
	}

	runes := []rune(in)
	for index := 2; index < len(runes); {
		if runes[index] == runes[index-1] && runes[index-1] == runes[index-2] {
			copy(runes[index:], runes[index+1:])
			runes = runes[:len(runes)-1]

		} else {
			index++
		}
	}
	for _, seq := range seqs {
		runes = passwordPrune(runes, seq)
	}
	if len(extra) != 0 {
		for _, seq := range extra[0] {
			runes = passwordPrune(runes, []rune(seq))
			runes = passwordPrune(runes, []rune(ustr.Reverse(seq)))
		}
	}

	entropy = float64(len(runes)) * math.Log2(float64(pool))

	return entropy, entropy >= 65.0
}
