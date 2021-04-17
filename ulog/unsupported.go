// +build windows

package ulog

import "fmt"

type Syslog struct{}

func DialSyslog(network, raddr string, priority int, tag string) (handle *Syslog, err error) {
	return nil, fmt.Errorf("unsupported")
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
