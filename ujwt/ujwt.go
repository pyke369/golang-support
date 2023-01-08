package ujwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func Encode(claims map[string]any, expire time.Time, secret string, kid ...string) (token string, err error) {
	var block *pem.Block

	alg := "HS256"
	if secret == "" {
		alg = "none"
	} else if len(kid) != 0 {
		rest := []byte(secret)
		for {
			if block, rest = pem.Decode(rest); block == nil {
				return "", fmt.Errorf("ujwt: invalid private key")
			}
			if block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" {
				if block.Type == "RSA PRIVATE KEY" {
					alg = "RS256"
				} else {
					alg = "ES256"
				}
				break
			}
		}
	}
	token = `{"typ":"JWT","alg":"` + alg + `"`
	if len(kid) != 0 {
		token += `,"kid":"` + kid[0] + `"`
	}
	token = base64.RawURLEncoding.EncodeToString([]byte(token+`}`)) + "."
	if claims == nil {
		claims = map[string]any{}
	}
	if !expire.IsZero() {
		claims["exp"] = expire.Unix()
	}
	marshaled, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	token += base64.RawURLEncoding.EncodeToString(marshaled)
	if alg == "none" {
		token += "."
	} else if alg == "HS256" {
		signature := hmac.New(sha256.New, []byte(secret))
		signature.Write([]byte(token))
		token += "." + base64.RawURLEncoding.EncodeToString(signature.Sum(nil))
	} else if alg == "RS256" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("ujwt: %v", err)
		}
		sum := sha256.Sum256([]byte(token))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			return "", fmt.Errorf("ujwt: %v", err)
		}
		token += "." + base64.RawURLEncoding.EncodeToString(signature)
	} else if alg == "ES256" {
		var signature [64]byte

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("ujwt: %v", err)
		}
		if key.Curve.Params().BitSize != 256 {
			return "", fmt.Errorf("ujwt: invalid elliptic curve size %d", key.Curve.Params().BitSize)
		}
		sum := sha256.Sum256([]byte(token))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return "", fmt.Errorf("ujwt: %v", err)
		}
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		token += "." + base64.RawURLEncoding.EncodeToString(signature[:])
	}
	return
}

func Decode(token string, secrets []string) (claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("ujwt: invalid token format")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	header := map[string]string{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, err
	}
	if (header["typ"] != "" && header["typ"] != "JWT") || (header["alg"] != "none" && header["alg"] != "HS256" && header["alg"] != "RS256" && header["alg"] != "ES256") {
		return nil, fmt.Errorf("ujwt: unsupported token format")
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if len(secrets) > 0 && header["alg"] != "none" {
		pass := false
		for _, secret := range secrets {
			if header["alg"] == "HS256" {
				signature := hmac.New(sha256.New, []byte(secret))
				signature.Write([]byte(parts[0] + "." + parts[1]))
				if hmac.Equal(signature.Sum(nil), decoded) {
					pass = true
				}
			} else {
				var block *pem.Block

				rest := []byte(secret)
				for {
					if block, rest = pem.Decode(rest); block == nil {
						break
					}
					if block.Type == "PUBLIC KEY" {
						if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
							switch key := key.(type) {
							case *rsa.PublicKey:
								if header["alg"] == "RS256" && len(decoded) == 256 {
									sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
									pass = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], decoded) == nil
								}
							case *ecdsa.PublicKey:
								if header["alg"] == "ES256" && len(decoded) == 64 {
									sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
									pass = ecdsa.Verify(key, sum[:], big.NewInt(0).SetBytes(decoded[:32]), big.NewInt(0).SetBytes(decoded[32:]))
								}
							}
						}
					}
				}
			}
			if pass == true {
				break
			}
		}
		if !pass {
			return nil, fmt.Errorf("ujwt: invalid signature")
		}
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}
	if _, ok := claims["exp"]; ok {
		if expire, ok := claims["exp"].(float64); !ok {
			return claims, fmt.Errorf("ujwt: invalid expiration claim")
		} else if time.Now().After(time.Unix(int64(expire), 0)) {
			return claims, fmt.Errorf("ujwt: expired token")
		}
	}
	return
}
