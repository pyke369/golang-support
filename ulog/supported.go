// +build !windows

package ulog

import "log/syslog"

type Syslog struct {
	*syslog.Writer
}

func DialSyslog(network, raddr string, priority int, tag string) (handle *Syslog, err error) {
	if handle, err := syslog.Dial(network, raddr, syslog.Priority(priority), tag); err == nil {
		return &Syslog{handle}, nil
	} else {
		return nil, err
	}
}
