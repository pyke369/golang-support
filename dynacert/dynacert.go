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
		return nil, errors.New(`dynacert: no loaded certificate`)
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
	return nil, errors.New(`dynacert: no matching certificate`)
}

func IntermediateTLSConfig(selector func(*tls.ClientHelloInfo) (*tls.Certificate, error), input ...*tls.Config) (output *tls.Config) {
	if len(input) > 0 && input[0] != nil {
		output = input[0].Clone()
	} else {
		output = &tls.Config{}
	}
	output.MinVersion = tls.VersionTLS12
	output.CipherSuites = []uint16{
		// TLS 1.3
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		// TLS 1.2
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
	if selector != nil {
		output.GetCertificate = selector
	}
	return
}
