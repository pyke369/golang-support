//go:build go1.24

package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/file"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/uhash"
)

// see https://akkadia.org/drepper/SHA-crypt.txt
var cryptb64 = base64.NewEncoding("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").WithPadding(base64.NoPadding)

func Crypt512(in, salt string, rounds int) (out string, err error) {
	in, salt = strings.TrimSpace(in), strings.TrimSpace(salt)
	if len(in) > 128 {
		return "", errors.New("auth: password too long")
	}

	out = "$6$"
	if rounds <= 0 {
		rounds = 100000
	}
	if rounds != 5000 {
		rounds = max(100000, min(1000000, rounds))
		out += "rounds=" + strconv.Itoa(rounds) + "$"
	}
	salt = salt[:min(16, len(salt))]
	if salt != "" && !rcache.Get(`^[\./0-9A-Za-z]{1,16}$`).MatchString(salt) {
		return "", errors.New("auth: invalid salt")
	}
	if salt == "" {
		value := make([]byte, 12)
		rand.Read(value)
		salt = cryptb64.EncodeToString(value)
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
	return out + string(C[:86]), nil
}

func Password(in string, values []string) (match bool, entry string) {
	if len(values) == 0 {
		return false, ""
	}

	login, password, checked := "", in, false
	if parts := strings.SplitN(in, ":", 2); len(parts) >= 2 {
		login, password = parts[0], parts[1]
	}
	for _, value := range values {
		check := value
		if login != "" {
			if parts := strings.Split(check, ":"); len(parts) < 2 || login != parts[0] {
				continue

			} else {
				check = parts[1]
			}
		}
		if check != "" && (check[0] == '!' || check[0] == '*') {
			continue
		}

		if parts := strings.Split(check, "$"); len(parts) >= 4 && parts[0] == "" && parts[2] != "" && parts[3] != "" {
			checked = true
			switch parts[1] {
			case "6":
				rounds, salt := 5000, parts[2]
				if len(parts) > 4 && strings.HasPrefix(parts[2], "rounds=") {
					if value, err := strconv.Atoi(parts[2][7:]); err == nil {
						rounds = value
					}
					salt = parts[3]
				}
				if encrypted, err := Crypt512(password, salt, rounds); err == nil {
					if subtle.ConstantTimeCompare([]byte(encrypted), []byte(check)) == 1 {
						parts := strings.Split(value, ":")
						if len(parts) >= 2 {
							parts[1] = "*"

						} else {
							parts[0] = "*"
						}
						return true, strings.Join(parts, ":")
					}
				}

			case "2", "2a":
				// TODO add bcrypt support

			case "y":
				// TODO add yescrypt support

			case "?":
				// TODO add argon2 support
			}
		}
	}
	if !checked {
		Crypt512(password, uhash.RandKey(16), 0)
	}

	return false, ""
}

func PasswordConfig(in string, config *uconfig.UConfig, path string) (match bool, entry string) {
	return Password(in, config.Strings(path))
}

func PasswordFile(in, path string) (match bool, entry string) {
	lines := file.Read(path, map[string]any{"options": "trim comment"})
	if len(lines) == 0 {
		return false, ""
	}

	return Password(in, lines)
}
