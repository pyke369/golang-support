package dynacert

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

type cert struct {
	inline   bool
	match    string
	public   string
	private  string
	cert     *tls.Certificate
	modified time.Time
}

type DYNACERT struct {
	certs []*cert
	last  int64
	mu    sync.RWMutex
}

func (d *DYNACERT) Add(match, public, private string) {
	d.mu.Lock()
	d.certs = append(d.certs, &cert{match: strings.TrimSpace(match), public: strings.TrimSpace(public), private: strings.TrimSpace(private)})
	d.mu.Unlock()
	atomic.StoreInt64(&d.last, time.Now().Add(-time.Minute).UnixNano())
}

func (d *DYNACERT) Inline(match string, public, private []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	value, err := tls.X509KeyPair(public, private)
	if err != nil {
		return ustr.Wrap(err, "dynacert")
	}
	d.certs = append(d.certs, &cert{match: strings.TrimSpace(match), inline: true, cert: &value})

	return nil
}

func (d *DYNACERT) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.certs = nil
}

func (d *DYNACERT) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.certs)
}

func (d *DYNACERT) GetCertificate(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	if time.Now().UnixNano()-atomic.LoadInt64(&d.last) >= int64(15*time.Second) {
		var info os.FileInfo

		atomic.StoreInt64(&d.last, time.Now().UnixNano())
		d.mu.Lock()
		for _, cert := range d.certs {
			if cert.inline {
				continue
			}
			if info, err = os.Stat(cert.public); err == nil {
				if info.ModTime().Sub(cert.modified) != 0 {
					if value, err := tls.LoadX509KeyPair(cert.public, cert.private); err == nil {
						cert.cert, cert.modified = &value, info.ModTime()
					}
				}
			}
		}
		d.mu.Unlock()
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.certs) == 0 {
		return nil, errors.New(`dynacert: no certificate loaded`)
	}
	if hello != nil && hello.ServerName != "" {
		name := hello.ServerName
		if value, _, err := net.SplitHostPort(name); err == nil {
			name = value
		}
		for _, cert := range d.certs {
			if cert.match != "" && cert.match != "*" && cert.cert != nil && rcache.Get(cert.match).MatchString(name) {
				return cert.cert, nil
			}
		}
	}
	for _, cert := range d.certs {
		if (cert.match == "" || cert.match == "*") && cert.cert != nil {
			return cert.cert, nil
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
