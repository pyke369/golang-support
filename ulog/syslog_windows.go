//go:build windows

package ulog

import "errors"

type syslogWriter struct{}

func dialSyslog(network, raddr string, priority int, tag string) (handle *syslogWriter, err error) {
	return nil, errors.New("unsupported")
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
