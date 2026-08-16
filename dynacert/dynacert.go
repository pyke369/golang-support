package dynacert

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

type cert struct {
	public   string
	private  string
	match    string
	matcher  *regexp.Regexp
	cert     atomic.Pointer[tls.Certificate]
	modified time.Time
}

type dynacert struct {
	mu     sync.RWMutex
	certs  []*cert
	reload chan struct{}
}

func New() (d *dynacert) {
	d = &dynacert{reload: make(chan struct{})}
	go func(d *dynacert) {
		ticker := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-d.reload:
			case <-ticker.C:
			}

			d.mu.RLock()
			certs, updated := slices.Clone(d.certs), false
			d.mu.RUnlock()
			for _, entry := range certs {
				if entry.public != "" && entry.private != "" {
					if info, err := os.Stat(entry.public); err == nil {
						if info.ModTime().Sub(entry.modified) != 0 {
							if value, err := tls.LoadX509KeyPair(entry.public, entry.private); err == nil {
								entry.modified, updated = info.ModTime(), true
								entry.cert.Store(&value)
							}
						}
					}
				}
				if value := entry.cert.Load(); value != nil && value.Leaf != nil {
					if time.Now().Before(value.Leaf.NotBefore) || time.Now().After(value.Leaf.NotAfter) {
						updated = true
						entry.cert.Store(nil)
					}
				}
			}
			if updated {
				d.mu.Lock()
				d.certs = certs
				d.mu.Unlock()
			}
		}
	}(d)

	return
}

func (d *dynacert) add(match, public, private string, certificate *tls.Certificate) (err error) {
	var matcher *regexp.Regexp

	reload := false
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if reload {
			d.reload <- struct{}{}
		}
	}()

	match, public, private = strings.TrimSpace(match), strings.TrimSpace(public), strings.TrimSpace(private)
	if match == "" || match == "*" {
		match = "*"
	}
	if strings.HasPrefix(match, "~") {
		rmatch := strings.TrimSpace(strings.TrimPrefix(match, "~"))
		if rmatch == "" {
			return errors.New("dynacert: empty matching regexp")
		}
		matcher, err = regexp.Compile("^(?:" + strings.TrimSuffix(strings.TrimPrefix(rmatch, "^"), "$") + ")$")
		if err != nil {
			return ustr.Wrap(err, "dynacert")
		}
	}

	exists := -1
	for index, entry := range d.certs {
		if entry.match == match {
			exists = index
			break
		}
	}

	if certificate == nil {
		if exists >= 0 {
			if d.certs[exists].public != public || d.certs[exists].private != private {
				d.certs[exists] = &cert{public: public, private: private, match: match, matcher: matcher}
				reload = true
			}

		} else {
			d.certs = append(d.certs, &cert{public: public, private: private, match: match, matcher: matcher})
			reload = true
		}

	} else {
		if exists >= 0 {
			d.certs[exists].cert.Store(certificate)

		} else {
			value := &cert{match: match, matcher: matcher}
			value.cert.Store(certificate)
			d.certs = append(d.certs, value)
		}
	}

	return nil
}

func (d *dynacert) Add(match, public, private string) error {
	return d.add(match, public, private, nil)
}

func (d *dynacert) Inline(match string, public, private []byte) error {
	value, err := tls.X509KeyPair(public, private)
	if err != nil {
		return ustr.Wrap(err, "dynacert")
	}

	return d.add(match, "", "", &value)
}

func (d *dynacert) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.certs = nil
}

func (d *dynacert) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.certs)
}

func (d *dynacert) GetCertificate(hello *tls.ClientHelloInfo) (out *tls.Certificate, err error) {
	var fallback *cert

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.certs) == 0 {
		return nil, errors.New(`dynacert: no certificate loaded`)
	}

	name := ""
	if hello != nil && hello.ServerName != "" {
		name = hello.ServerName
		if value, _, err := net.SplitHostPort(name); err == nil {
			name = value
		}
	}
	for pass := 1; pass <= 2; pass++ {
		for _, entry := range d.certs {
			if entry.match == "*" {
				fallback = entry
			}
			if name == "" {
				continue
			}
			if (pass == 1 && entry.matcher == nil && name == entry.match) ||
				(pass == 2 && entry.matcher != nil && entry.matcher.MatchString(name)) {
				if value := entry.cert.Load(); value != nil {
					return value, nil
				}
			}
		}
	}
	if fallback != nil {
		if value := fallback.cert.Load(); value != nil {
			return value, nil
		}
	}

	return nil, errors.New(`dynacert: no matching valid certificate`)
}

func (d *dynacert) TLSConfig(in ...*tls.Config) (out *tls.Config) {
	if len(in) > 0 && in[0] != nil {
		out = in[0].Clone()

	} else {
		out = &tls.Config{}
	}
	out.MinVersion, out.GetCertificate = tls.VersionTLS13, d.GetCertificate
	return
}
