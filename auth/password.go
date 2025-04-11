package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/uconfig"
)

// see https://akkadia.org/drepper/SHA-crypt.txt
var cryptb64 = base64.NewEncoding("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").WithPadding(base64.NoPadding)

func crypt512(key, salt string, rounds int) (out string) {
	out = "$6$"
	if rounds == 0 {
		rounds = 5000
	}
	rounds = max(1000, min(999999999, rounds))
	if rounds != 5000 {
		out += "rounds=" + strconv.Itoa(rounds) + "$"
	}
	salt = salt[:min(16, len(salt))]
	if salt == "" {
		value := make([]byte, 6)
		rand.Read(value)
		salt = cryptb64.EncodeToString(value)
	}
	out += salt + "$"

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
	return out + string(C[:86])
}

func Password(in string, values []string, fallback bool) (match bool, entry string) {
	if len(values) > 0 {
		login, password := "", strings.TrimSpace(in)
		if parts := strings.Split(in, ":"); len(parts) >= 2 {
			login, password = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
		for _, value := range values {
			check := strings.TrimSpace(value)
			if len(check) > 1 && check[0] == '@' {
				if match, value := PasswordFile(in, strings.TrimSpace(check[1:]), fallback); match {
					return true, value
				}

			} else {
				if login != "" {
					if parts := strings.Split(check, ":"); len(parts) < 2 || login != strings.TrimSpace(parts[0]) {
						continue

					} else {
						check = strings.TrimSpace(parts[1])
					}
				}
				if check != "" && (check[0] == '!' || check[0] == '*') {
					continue
				}

				if parts := strings.Split(check, "$"); len(parts) >= 4 && parts[0] == "" && parts[1] == "6" && parts[2] != "" && parts[3] != "" {
					rounds, salt := 5000, parts[2]
					if len(parts) > 4 && strings.HasPrefix(parts[2], "rounds=") {
						rounds, _ = strconv.Atoi(parts[2][7:])
						salt = parts[3]
					}
					if crypt512(password, salt, rounds) == check {
						return true, value
					}

					// TODO add yescrypt support

				} else if password == check {
					return true, value
				}
			}
		}
		return false, ""
	}
	return fallback, ""
}

func PasswordConfig(in string, config *uconfig.UConfig, path string, fallback bool) (match bool, entry string) {
	return Password(in, config.Strings(path), fallback)
}

func PasswordFile(in, path string, fallback bool) (match bool, entry string) {
	lines := []string{}
	if content, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if (len(line) >= 1 && line[0] != '#') || (len(line) >= 2 && line[0] != '/' && line[1] != '/') {
				lines = append(lines, line)
			}
		}
	}
	return Password(in, lines, fallback)
}
