package dynacert

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

type cert struct {
	inline   bool
	public   string
	private  string
	matcher  *regexp.Regexp
	cert     *tls.Certificate
	modified time.Time
}

type DYNACERT struct {
	mu       sync.RWMutex
	wildcard *cert
	certs    []*cert
	last     int64
}

func (d *DYNACERT) Add(match, public, private string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	match = strings.TrimSpace(match)
	if match == "" || match == "*" {
		d.wildcard = &cert{public: strings.TrimSpace(public), private: strings.TrimSpace(private)}
		return nil
	}

	if match[0] != '^' {
		match = "^" + match
	}
	if match[len(match)-1] != '$' {
		match += "$"
	}
	matcher, err := regexp.Compile(match)
	if err != nil {
		return ustr.Wrap(err, "dynacert")
	}
	d.certs = append(d.certs, &cert{matcher: matcher, public: strings.TrimSpace(public), private: strings.TrimSpace(private)})
	atomic.StoreInt64(&d.last, time.Now().Add(-time.Minute).UnixNano())

	return nil
}

func (d *DYNACERT) Inline(match string, public, private []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	value, err := tls.X509KeyPair(public, private)
	if err != nil {
		return ustr.Wrap(err, "dynacert")
	}
	match = strings.TrimSpace(match)
	if match == "" || match == "*" {
		d.wildcard = &cert{inline: true, cert: &value}
		return nil
	}
	if match[0] != '^' {
		match = "^" + match
	}
	if match[len(match)-1] != '$' {
		match += "$"
	}
	matcher, err := regexp.Compile(match)
	if err != nil {
		return ustr.Wrap(err, "dynacert")
	}
	d.certs = append(d.certs, &cert{inline: true, matcher: matcher, cert: &value})

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
			if cert.matcher.MatchString(name) {
				return cert.cert, nil
			}
		}
	}
	if d.wildcard != nil {
		return d.wildcard.cert, nil
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
