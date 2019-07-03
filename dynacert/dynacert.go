package dynacert

import (
	"crypto/tls"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

type DYNACERT struct {
	Public, Key  string
	Config       [][3]string
	certificates []*tls.Certificate
	modified     []time.Time
	last         time.Time
	sync.RWMutex
}

func (this *DYNACERT) GetCertificate(client *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	if this.Config == nil || this.certificates == nil || this.modified == nil {
		this.Lock()
		if this.Config == nil {
			this.Config = [][3]string{}
			if this.Public != "" && this.Key != "" {
				this.Config = append(this.Config, [3]string{"", this.Public, this.Key})
				this.Public, this.Key = "", ""
			}
		}
		if this.certificates == nil {
			this.certificates = make([]*tls.Certificate, len(this.Config))
		}
		if this.modified == nil {
			this.modified = make([]time.Time, len(this.Config))
		}
		this.Unlock()
	}

	if time.Now().Sub(this.last) >= time.Minute {
		this.Lock()
		if time.Now().Sub(this.last) >= time.Minute {
			var info os.FileInfo

			this.last = time.Now()
			for index, config := range this.Config {
				if info, err = os.Stat(config[1]); err == nil {
					if _, err = os.Stat(config[2]); err == nil {
						if info.ModTime().Sub(this.modified[index]) != 0 {
							if certificate, err := tls.LoadX509KeyPair(config[1], config[2]); err == nil {
								this.certificates[index] = &certificate
								this.modified[index] = info.ModTime()
							}
						}
					}
				}
			}
		}
		this.Unlock()
	}

	this.RLock()
	defer this.RUnlock()
	if len(this.certificates) == 0 {
		return nil, errors.New("no loaded certificate")
	}
	if client != nil && client.ServerName != "" {
		for index, config := range this.Config {
			if config[0] != "" && config[0] != "*" && this.certificates[index] != nil {
				if matcher := rcache.Get(config[0]); matcher != nil && matcher.MatchString(client.ServerName) {
					return this.certificates[index], nil
				}
			}
		}
	}
	for index, config := range this.Config {
		if (config[0] == "" || config[0] == "*") && this.certificates[index] != nil {
			return this.certificates[index], nil
		}
	}
	return nil, errors.New("no matching certificate")
}

func ModernTLSConfig(input func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (output *tls.Config) {
	output = &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
		MinVersion:               tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if input != nil {
		output.GetCertificate = input
	}
	return
}
