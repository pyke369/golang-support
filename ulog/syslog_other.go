//go:build !windows

package ulog

import "log/syslog"

type syslogWriter struct {
	*syslog.Writer
}

func dialSyslog(network, raddr string, priority int, tag string) (handle *syslogWriter, err error) {
	if handle, err := syslog.Dial(network, raddr, syslog.Priority(priority), tag); err == nil {
		return &syslogWriter{handle}, nil

	} else {
		return nil, err
	}
}
