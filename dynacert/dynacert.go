package dynacert

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type DYNACERT struct {
	Public, Key    string
	Certificate    *tls.Certificate
	Last, Modified time.Time
	sync.RWMutex
}

func (this *DYNACERT) GetCertificate(*tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	var info os.FileInfo

	if this.Certificate == nil || time.Now().Sub(this.Last) >= 10*time.Second {
		this.Last = time.Now()
		if info, err = os.Stat(this.Public); err != nil {
			return nil, err
		}
		if _, err = os.Stat(this.Key); err != nil {
			return nil, err
		}
		if this.Certificate == nil || info.ModTime().Sub(this.Modified) != 0 {
			if certificate, err := tls.LoadX509KeyPair(this.Public, this.Key); err != nil {
				return nil, err
			} else {
				this.Lock()
				this.Modified = info.ModTime()
				this.Certificate = &certificate
				this.Unlock()
			}
		}
	}
	this.RLock()
	defer this.RUnlock()
	return this.Certificate, nil
}
