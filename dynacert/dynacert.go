package dynacert

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

type certificate struct {
	predicate   string
	public      string
	private     string
	certificate *tls.Certificate
	modified    time.Time
}

type DYNACERT struct {
	sync.RWMutex
	certificates []*certificate
	last         time.Time
}

func (d *DYNACERT) Add(predicate, public, private string) {
	d.Lock()
	d.certificates = append(d.certificates, &certificate{predicate: strings.TrimSpace(predicate), public: strings.TrimSpace(public), private: strings.TrimSpace(private)})
	d.last = time.Now().Add(-time.Minute)
	d.Unlock()
}

func (d *DYNACERT) Clear() {
	d.Lock()
	d.certificates = nil
	d.Unlock()
}

func (d *DYNACERT) Count() int {
	d.RLock()
	defer d.RUnlock()
	return len(d.certificates)
}

func (d *DYNACERT) GetCertificate(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	if time.Since(d.last) >= 15*time.Second {
		d.Lock()
		if time.Since(d.last) >= 15*time.Second {
			var info os.FileInfo

			d.last = time.Now()
			for _, certificate := range d.certificates {
				if info, err = os.Stat(certificate.public); err == nil {
					if info.ModTime().Sub(certificate.modified) != 0 {
						if value, err := tls.LoadX509KeyPair(certificate.public, certificate.private); err == nil {
							certificate.certificate, certificate.modified = &value, info.ModTime()
						}
					}
				}
			}
		}
		d.Unlock()
	}
	d.RLock()
	defer d.RUnlock()
	if len(d.certificates) == 0 {
		return nil, errors.New(`dynacert: no certificate loaded`)
	}
	if hello != nil && hello.ServerName != "" {
		name := hello.ServerName
		if value, _, err := net.SplitHostPort(name); err == nil {
			name = value
		}
		for _, certificate := range d.certificates {
			if certificate.predicate != "" && certificate.predicate != "*" && certificate.certificate != nil {
				if matcher := rcache.Get(certificate.predicate); matcher != nil && matcher.MatchString(name) {
					return certificate.certificate, nil
				}
			}
		}
	}
	for _, certificate := range d.certificates {
		if (certificate.predicate == "" || certificate.predicate == "*") && certificate.certificate != nil {
			return certificate.certificate, nil
		}
	}
	return nil, errors.New(`dynacert: no matching certificate`)
}

func (d *DYNACERT) TLSConfig(in ...*tls.Config) (out *tls.Config) {
	if len(in) > 0 && in[0] != nil {
		out = in[0].Clone()
	} else {
		out = &tls.Config{}
	}
	out.MinVersion, out.GetCertificate = tls.VersionTLS13, d.GetCertificate
	return
}
