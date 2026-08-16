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
	"maps"
	"math/big"
	"regexp"
	"slices"
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
	claimMatcher = regexp.MustCompile(`^[0-9a-zA-Z_]{3,64}$`)
)

func TokenEncode(typ, kid, key string, alg Alg, expire time.Time, claims map[string]any) (out string, err error) {
	var der *pem.Block

	if typ == "" {
		typ = "JWT"
	}
	if !strings.Contains(strings.ToLower(typ), "jwt") {
		return "", errors.New("auth: invalid token type")
	}
	if expire.Before(time.Now()) {
		return "", errors.New("auth: expire must be in the future")
	}
	if expire.After(time.Now().Add(time.Hour * 24 * 365)) {
		return "", errors.New("auth: expire must be less than a year")
	}
	if alg == AlgHS256 {
		if len(key) < 32 {
			return "", errors.New("auth: invalid key")
		}

	} else {
		if der, _ = pem.Decode([]byte(key)); der == nil || !strings.Contains(der.Type, "PRIVATE KEY") {
			return "", errors.New("auth: invalid private key")
		}
	}

	if claims == nil {
		return "", errors.New("auth: no claim provided")
	}
	for k := range claims {
		if !claimMatcher.MatchString(k) {
			return "", errors.New("auth: invalid claim name")
		}
	}
	if value := j.String(claims["iss"]); value == "" {
		return "", errors.New("auth: missing or invalid 'iss' claim")
	}
	if value := j.StringSlice(claims["aud"], true); len(value) == 0 {
		return "", errors.New("auth: missing or invalid 'aud' claim")
	}
	if value := j.String(claims["sub"]); value == "" {
		return "", errors.New("auth: missing or invalid 'sub' claim")
	}

	header := map[string]string{"typ": typ, "alg": string(alg)}
	if kid != "" {
		header["kid"] = kid
	}
	marshaled, err := json.Marshal(header)
	if err != nil {
		return "", ustr.Wrap(err, "auth")
	}
	token := base64.RawURLEncoding.AppendEncode([]byte{}, marshaled)
	token = append(token, '.')

	rclaims := maps.Clone(claims)
	rclaims["iat"], rclaims["nbf"], rclaims["exp"] = time.Now().Unix(), time.Now().Unix(), expire.Unix()
	marshaled, err = json.Marshal(rclaims)
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
			value, err := x509.ParsePKCS8PrivateKey(der.Bytes)
			if err != nil {
				return "", ustr.Wrap(err, "auth")
			}
			if value, ok := value.(*ecdsa.PrivateKey); ok {
				key = value

			} else {
				return "", errors.New("auth: invalid EC private key")
			}
		}
		if key.Curve.Params().BitSize != 256 {
			return "", errors.New("auth: unsupported EC size")
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

func TokenDecode(token string, keys map[Alg]any, claims map[string]any, extra ...time.Duration) (out map[string]any, err error) {
	if len(token) > 4<<10 {
		return nil, errors.New("auth: size exceeded")
	}
	if len(keys) == 0 {
		return nil, errors.New("auth: no key provided")
	}
	if claims == nil {
		return nil, errors.New("auth: no claim provided")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth: invalid token format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	header := map[string]any{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	if header["crit"] != nil {
		return nil, errors.New("auth: crit not supported")
	}
	if typ := j.String(header["typ"]); typ != "" && !strings.Contains(strings.ToLower(typ), "jwt") {
		return nil, errors.New("auth: invalid 'typ' claim")
	}
	alg, exists := algs[j.String(header["alg"])]
	if !exists {
		return nil, errors.New("auth: unsupported 'alg' claim")
	}
	if _, exists := keys[alg]; !exists {
		return nil, errors.New("auth: invalid key")
	}
	kid, key := j.String(header["kid"]), ""
	if kid == "" {
		key = strings.TrimSpace(j.String(keys[alg]))

	} else {
		key = strings.TrimSpace(j.StringMap(keys[alg])[kid])
	}
	if key == "" {
		return nil, errors.New("auth: invalid key")
	}

	decoded, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	pass, input := false, []byte(parts[0]+"."+parts[1])
	if alg == AlgHS256 {
		if len(key) >= 32 {
			signature := hmac.New(sha256.New, []byte(key))
			signature.Write(input)
			if hmac.Equal(signature.Sum(nil), decoded) {
				pass = true
			}
		}

	} else {
		if der, _ := pem.Decode([]byte(key)); der != nil && strings.Contains(der.Type, "PUBLIC KEY") {
			if key, err := x509.ParsePKIXPublicKey(der.Bytes); err == nil {
				switch alg {
				case AlgRS256, AlgPS256:
					if key, ok := key.(*rsa.PublicKey); ok && key.N.BitLen() >= 2048 && len(decoded) == key.Size() {
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
	}
	if !pass {
		return nil, errors.New("auth: invalid signature")
	}

	decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	rclaims := map[string]any{}
	if err := json.Unmarshal(decoded, &rclaims); err != nil {
		return nil, ustr.Wrap(err, "auth")
	}
	iat, exp, iss, aud := int64(j.Number(rclaims["iat"])), int64(j.Number(rclaims["exp"])), j.String(rclaims["iss"]), j.StringSlice(rclaims["aud"], true)
	if iat == 0 || exp == 0 || iss == "" || len(aud) == 0 || j.String(rclaims["sub"]) == "" {
		return nil, errors.New("auth: missing mandatory claim")
	}
	for k := range rclaims {
		if !claimMatcher.MatchString(k) {
			return nil, errors.New("auth: invalid claim name")
		}
	}

	skew := 30 * time.Second
	if len(extra) != 0 {
		skew = max(0, min(2*time.Minute, extra[0]))
	}
	if time.Now().Add(skew).Before(time.Unix(int64(iat), 0)) {
		return nil, errors.New("auth: invalid 'iat' claim")
	}
	if time.Now().Add(-skew).After(time.Unix(int64(exp), 0)) {
		return nil, errors.New("auth: expired")
	}
	if exp <= iat || exp-iat > 3600*24*365 {
		return nil, errors.New("auth: invalid 'exp' claim")
	}
	if value := j.Number(rclaims["nbf"]); value != 0 {
		if time.Now().Add(skew).Before(time.Unix(int64(value), 0)) {
			return nil, errors.New("auth: not yet valid")
		}
	}
	if j.String(claims["iss"]) != iss {
		return nil, errors.New("auth: invalid 'iss' claim")
	}
	pass = false
	for _, value := range j.StringSlice(claims["aud"], true) {
		if slices.Contains(aud, value) {
			pass = true
			break
		}
	}
	if !pass {
		return nil, errors.New("auth: invalid 'aud' claim")
	}

	for k, v := range claims {
		if slices.Contains([]string{"iat", "exp", "nbf", "iss", "aud"}, k) {
			continue
		}
		claim := j.StringSlice(rclaims[k], true)
		if len(claim) == 0 {
			return nil, errors.New("auth: missing '" + k + "' claim")
		}
		pass = false
		for _, value := range j.StringSlice(v, true) {
			if slices.Contains(claim, value) {
				pass = true
				break
			}
		}
		if !pass {
			return nil, errors.New("auth: invalid '" + k + "' claim")
		}
	}

	return maps.Clone(rclaims), nil
}
