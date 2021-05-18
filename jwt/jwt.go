package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func Encode(claims map[string]interface{}, expire time.Time, secret string) (token string, err error) {
	token = base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"HS256"}`)) + "."
	if claims == nil {
		claims = map[string]interface{}{}
	}
	if !expire.IsZero() {
		claims["exp"] = expire.Unix()
	}
	marshaled, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	token += base64.RawURLEncoding.EncodeToString(marshaled)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	token += "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return
}

func Decode(token, secret string) (claims map[string]interface{}, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: invalid token format")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	header := map[string]string{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, err
	}
	if header["typ"] != "JWT" || header["alg"] != "HS256" {
		return nil, fmt.Errorf("jwt: unsupported token format")
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(mac.Sum(nil), decoded) {
		return nil, fmt.Errorf("jwt: invalid signature")
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
			return nil, fmt.Errorf("jwt: invalid expiration claim")
		} else if time.Now().After(time.Unix(int64(expire), 0)) {
			return nil, fmt.Errorf("jwt: expired token")
		}
	}
	return
}
