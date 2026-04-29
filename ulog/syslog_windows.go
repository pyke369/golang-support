//go:build windows

package ulog

import (
	"errors"

	"github.com/pyke369/golang-support/ustr"
)

type syslogWriter struct{}

func dialSyslog(network, raddr string, priority int, tag string) (handle *syslogWriter, err error) {
	return nil, ustr.Wrap(errors.ErrUnsupported, "ulog")
}

func (s *syslogWriter) Close() {
}

func (s *syslogWriter) Debug(m string) {
}

func (s *syslogWriter) Err(m string) {
}

func (s *syslogWriter) Info(m string) {
}

func (s *syslogWriter) Warning(m string) {
}
