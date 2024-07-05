//go:build windows

package ulog

import "errors"

type syslogWriter struct{}

func dialSyslog(network, raddr string, priority int, tag string) (handle *syslogWriter, err error) {
	return nil, errors.New("unsupported")
}
func (this *s) Close() {
}
func (this *s) Debug(m string) {
}
func (this *s) Err(m string) {
}
func (this *s) Info(m string) {
}
func (this *s) Warning(m string) {
}
