//go:build windows

package ulog

import "errors"

type Syslog struct{}

func DialSyslog(network, raddr string, priority int, tag string) (handle *Syslog, err error) {
	return nil, errors.New("unsupported")
}
func (this *Syslog) Close() {
}
func (this *Syslog) Debug(m string) {
}
func (this *Syslog) Err(m string) {
}
func (this *Syslog) Info(m string) {
}
func (this *Syslog) Warning(m string) {
}
