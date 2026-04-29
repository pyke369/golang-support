package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/ustr"
)

type Alg string

const (
	AlgHS256 Alg = "HS256"
	AlgRS256 Alg = "RS256"
	AlgPS256 Alg = "PS256"
	AlgES256 Alg = "ES256"
	AlgEDDSA Alg = "EdDSA"
)

var (
	algs = map[string]Alg{
		string(AlgHS256): AlgHS256,
		string(AlgRS256): AlgRS256,
		string(AlgPS256): AlgPS256,
		string(AlgES256): AlgES256,
		string(AlgEDDSA): AlgEDDSA,
	}
)

func TokenEncode(claims map[string]any, expire time.Time, alg Alg, key string, kid ...string) (out string, err error) {
	var (
		der   *pem.Block
		token []byte
	)

	header := map[string]string{"typ": "JWT", "alg": string(alg)}
	if alg == AlgHS256 {
		if len(key) < 32 {
			return "", errors.New("auth: invalid key")
		}

	} else {
		if der, _ = pem.Decode([]byte(key)); der == nil {
			return "", errors.New("auth: invalid private key")
		}
		if len(kid) != 0 {
			if kid[0] == "" {
				return "", errors.New("auth: invalid kid")
			}
			header["kid"] = kid[0]
		}
	}

	marshaled, err := json.Marshal(header)
	if err != nil {
		return "", ustr.Wrap(err, "auth")
	}
	token = base64.RawURLEncoding.AppendEncode(token, marshaled)
	token = append(token, '.')
	if claims == nil {
		claims = map[string]any{}
	}
	claims["iat"], claims["nbf"], claims["exp"] = time.Now().Unix(), time.Now().Unix(), expire.Unix()
	marshaled, err = json.Marshal(claims)
	if err != nil {
		return "", ustr.Wrap(err, "auth")
	}
	token = base64.RawURLEncoding.AppendEncode(token, marshaled)

	switch alg {
	case AlgHS256:
		signature := hmac.New(sha256.New, []byte(key))
		signature.Write(token)
		token = append(token, '.')
		token = base64.RawURLEncoding.AppendEncode(token, signature.Sum(nil))

	case AlgRS256, AlgPS256:
		var signature []byte

		value, err := x509.ParsePKCS8PrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "auth")
		}
		key, ok := value.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("auth: invalid RSA private key")
		}
		if key.N.BitLen() < 2048 {
			return "", errors.New("auth: unsupported RSA private key size")
		}
		sum := sha256.Sum256(token)
		if alg == AlgRS256 {
			signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])

		} else {
			signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], nil)
		}
		if err != nil {
			return "", ustr.Wrap(err, "auth")
		}
		token = append(token, '.')
		token = base64.RawURLEncoding.AppendEncode(token, signature)

	case AlgES256:
		var signature [64]byte

		key, err := x509.ParseECPrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "auth")
		}
		if key.Curve.Params().BitSize != 256 {
			return "", errors.New("auth: unsupported elliptic curve size")
		}
		sum := sha256.Sum256(token)
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return "", ustr.Wrap(err, "auth")
		}
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		token = append(token, '.')
		token = base64.RawURLEncoding.AppendEncode(token, signature[:])

	case AlgEDDSA:
		value, err := x509.ParsePKCS8PrivateKey(der.Bytes)
		if err != nil {
			return "", ustr.Wrap(err, "auth")
		}
		key, ok := value.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("auth: invalid EdDSA private key")
		}
		signature := ed25519.Sign(key, token)
		token = append(token, '.')
		token = base64.RawURLEncoding.AppendEncode(token, signature)
	}

	return string(token), nil
}

func TokenDecode(token string, keys map[Alg]any, extra ...map[string]any) (claims map[string]any, err error) {
	if len(keys) == 0 {
		return nil, errors.New("auth: no key provided")
	}
	if len(token) > 4<<10 {
		return nil, errors.New("auth: size exceeded")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth: invalid format")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	header := map[string]string{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	if header["typ"] != "JWT" {
		return nil, errors.New("auth: invalid token")
	}
	alg, exists := algs[header["alg"]]
	if !exists {
		return nil, errors.New("auth: invalid alg")
	}
	akeys, exists := keys[alg]
	if !exists {
		return nil, errors.New("auth: no key provided for alg")
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}

	pass, input := false, []byte(parts[0]+"."+parts[1])
	if alg == AlgHS256 {
		for _, key := range j.StringSlice(akeys, true) {
			if len(key) < 32 {
				continue
			}
			signature := hmac.New(sha256.New, []byte(key))
			signature.Write(input)
			if hmac.Equal(signature.Sum(nil), decoded) {
				pass = true
				break
			}
		}

	} else {
		kid := header["kid"]
		for id, key := range j.StringMap(akeys, true) {
			if kid != "" && kid != id {
				continue
			}

			if der, _ := pem.Decode([]byte(key)); der != nil {
				if key, err := x509.ParsePKIXPublicKey(der.Bytes); err == nil {
					switch alg {
					case AlgRS256, AlgPS256:
						if key, ok := key.(*rsa.PublicKey); ok && len(decoded) == key.Size() {
							sum := sha256.Sum256(input)
							if alg == AlgRS256 {
								pass = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], decoded) == nil

							} else {
								pass = rsa.VerifyPSS(key, crypto.SHA256, sum[:], decoded, nil) == nil
							}
						}

					case AlgES256:
						if key, ok := key.(*ecdsa.PublicKey); ok && key.Curve.Params().BitSize == 256 && len(decoded) == 64 {
							sum := sha256.Sum256(input)
							pass = ecdsa.Verify(key, sum[:], big.NewInt(0).SetBytes(decoded[:32]), big.NewInt(0).SetBytes(decoded[32:]))
						}

					case AlgEDDSA:
						if key, ok := key.(ed25519.PublicKey); ok && len(decoded) == 64 {
							pass = ed25519.Verify(key, input, decoded)
						}
					}
				}
			}

			if kid != "" || pass {
				break
			}
		}
	}

	if !pass {
		return nil, errors.New("auth: invalid signature")
	}

	decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, ustr.Wrap(err, "auth")
	}

	skew := 30 * time.Second
	if len(extra) != 0 {
		if value, ok := extra[0]["skew"].(time.Duration); ok {
			skew = value
		}
	}

	value, ok := claims["exp"].(float64)
	if !ok || time.Now().Add(-skew).After(time.Unix(int64(value), 0)) {
		return nil, errors.New("auth: expired")
	}

	if value, ok := claims["iat"].(float64); ok {
		if time.Now().Add(skew).Before(time.Unix(int64(value), 0)) {
			return nil, errors.New("auth: issued in future")
		}
	}
	if value, ok := claims["nbf"].(float64); ok {
		if time.Now().Add(skew).Before(time.Unix(int64(value), 0)) {
			return nil, errors.New("auth: not yet valid")
		}
	}
	if len(extra) != 0 {
		if value, ok := extra[0]["claims"].(map[string]string); ok {
			for k, v := range value {
				if value, ok := claims[k].(string); !ok || subtle.ConstantTimeCompare([]byte(value), []byte(v)) == 0 {
					return nil, errors.New("auth: invalid claim")
				}
			}
		}
	}

	return
}
