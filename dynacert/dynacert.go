package dynacert

import (
	"crypto/tls"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

type CERTIFICATE struct {
	public      string
	private     string
	certificate *tls.Certificate
	modified    time.Time
}

type DYNACERT struct {
	sync.RWMutex
	certificates map[string]*CERTIFICATE
	last         time.Time
}

func (this *DYNACERT) Add(predicate, public, private string) {
	this.Lock()
	if this.certificates == nil {
		this.certificates = map[string]*CERTIFICATE{}
	}
	this.certificates[strings.TrimSpace(predicate)] = &CERTIFICATE{public: strings.TrimSpace(public), private: strings.TrimSpace(private)}
	this.last = time.Now().Add(-time.Minute)
	this.Unlock()
}

func (this *DYNACERT) Clear() {
	this.Lock()
	this.certificates = map[string]*CERTIFICATE{}
	this.Unlock()
}

func (this *DYNACERT) Count() int {
	this.RLock()
	defer this.RUnlock()
	return len(this.certificates)
}

func (this *DYNACERT) GetCertificate(client *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	if time.Now().Sub(this.last) >= time.Second*15 {
		this.Lock()
		if time.Now().Sub(this.last) >= time.Second*15 {
			var info os.FileInfo

			this.last = time.Now()
			for _, certificate := range this.certificates {
				if info, err = os.Stat(certificate.public); err == nil {
					if info.ModTime().Sub(certificate.modified) != 0 {
						if value, err := tls.LoadX509KeyPair(certificate.public, certificate.private); err == nil {
							certificate.certificate = &value
							certificate.modified = info.ModTime()
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
		for predicate, certificate := range this.certificates {
			if predicate != "" && predicate != "*" && certificate.certificate != nil {
				if matcher := rcache.Get(predicate); matcher != nil && matcher.MatchString(client.ServerName) {
					return certificate.certificate, nil
				}
			}
		}
	}
	for predicate, certificate := range this.certificates {
		if (predicate == "" || predicate == "*") && certificate.certificate != nil {
			return certificate.certificate, nil
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
