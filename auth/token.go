package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

func TokenEncode(claims map[string]any, expire time.Time, secret string, kid ...string) (token string, err error) {
	var der *pem.Block

	alg := "HS256"
	if len(kid) != 0 {
		if der, _ = pem.Decode([]byte(secret)); der == nil {
			return "", errors.New("token: invalid private key")
		}
		switch der.Type {
		case "RSA PRIVATE KEY":
			alg = "RS256"

		case "EC PRIVATE KEY":
			alg = "ES256"

		case "PRIVATE KEY":
			alg = "EdDSA"

		default:
			return "", errors.New("token: invalid private key type")
		}
	}
	if alg == "HS256" && len(secret) < 32 {
		return "", errors.New("token: invalid secret")
	}

	token = `{"typ":"JWT","alg":"` + alg + `"`
	if len(kid) != 0 {
		if value, err := json.Marshal(kid[0]); err == nil {
			token += `,"kid":` + string(value)
		}
	}
	token = base64.RawURLEncoding.EncodeToString([]byte(token+`}`)) + "."

	if claims == nil {
		claims = map[string]any{}
	}
	claims["iat"], claims["exp"] = time.Now().Unix(), expire.Unix()
	marshaled, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	token += base64.RawURLEncoding.EncodeToString(marshaled)

	switch alg {
	case "HS256":
		signature := hmac.New(sha256.New, []byte(secret))
		signature.Write([]byte(token))
		token += "." + base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	case "RS256":
		key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "token")
		}
		sum := sha256.Sum256([]byte(token))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			return "", ustr.Wrap(err, "token")
		}
		token += "." + base64.RawURLEncoding.EncodeToString(signature)

	case "ES256":
		var signature [64]byte

		key, err := x509.ParseECPrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "token")
		}
		if key.Curve.Params().BitSize != 256 {
			return "", errors.New("token: unsupported elliptic curve size")
		}
		sum := sha256.Sum256([]byte(token))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return "", ustr.Wrap(err, "token")
		}
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		token += "." + base64.RawURLEncoding.EncodeToString(signature[:])

	case "EdDSA":
		value, err := x509.ParsePKCS8PrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "token")
		}
		key, ok := value.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("token: invalid EdDSA private key")
		}
		signature := ed25519.Sign(key, []byte(token))
		token += "." + base64.RawURLEncoding.EncodeToString(signature)
	}

	return
}

func TokenDecode(token string, secrets []string, extra ...time.Duration) (claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token: invalid format")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	header := map[string]string{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, err
	}
	if header["typ"] != "JWT" || (header["alg"] != "HS256" && header["alg"] != "RS256" && header["alg"] != "ES256" && header["alg"] != "EdDSA") {
		return nil, errors.New("token: unsupported format")
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	pass := false
	for _, secret := range secrets {
		var der *pem.Block

		if der, _ = pem.Decode([]byte(secret)); der != nil && der.Type == "PUBLIC KEY" {
			if key, err := x509.ParsePKIXPublicKey(der.Bytes); err == nil {
				switch key := key.(type) {
				case *rsa.PublicKey:
					if header["alg"] == "RS256" && len(decoded) == key.Size() {
						sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
						pass = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], decoded) == nil
					}

				case *ecdsa.PublicKey:
					if header["alg"] == "ES256" && len(decoded) == 64 {
						sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
						pass = ecdsa.Verify(key, sum[:], big.NewInt(0).SetBytes(decoded[:32]), big.NewInt(0).SetBytes(decoded[32:]))
					}

				case ed25519.PublicKey:
					if header["alg"] == "EdDSA" && len(decoded) == 64 {
						pass = ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), decoded)
					}
				}
			}

		} else if header["alg"] == "HS256" {
			signature := hmac.New(sha256.New, []byte(secret))
			signature.Write([]byte(parts[0] + "." + parts[1]))
			if hmac.Equal(signature.Sum(nil), decoded) {
				pass = true
			}
		}

		if pass {
			break
		}
	}
	if !pass {
		return nil, errors.New("token: invalid signature")
	}

	skew := 30 * time.Second
	if len(extra) != 0 {
		skew = extra[0]
	}

	decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}

	exp, exists := claims["exp"]
	if !exists {
		return nil, errors.New("token: no expiration claim")
	}
	value, ok := exp.(float64)
	if !ok {
		return nil, errors.New("token: invalid expiration claim format")
	}
	if time.Now().Add(skew).After(time.Unix(int64(value), 0)) {
		return nil, errors.New("token: expired")
	}

	if value, exists := claims["iat"]; exists {
		if value, ok := value.(float64); !ok {
			return nil, errors.New("token: invalid issued-at claim format")

		} else if time.Now().Add(-skew).Before(time.Unix(int64(value), 0)) {
			return nil, errors.New("token: issued in future")
		}
	}
	if value, exists := claims["nbf"]; exists {
		if value, ok := value.(float64); !ok {
			return nil, errors.New("token: invalid not-before claim format")

		} else if time.Now().Add(-skew).Before(time.Unix(int64(value), 0)) {
			return nil, errors.New("token: not yet valid")
		}
	}

	return
}
