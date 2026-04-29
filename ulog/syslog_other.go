//go:build !windows

package ulog

import (
	"log/syslog"

	"github.com/pyke369/golang-support/ustr"
)

type syslogWriter struct {
	*syslog.Writer
}

func dialSyslog(network, raddr string, priority int, tag string) (handle *syslogWriter, err error) {
	writer, err := syslog.Dial(network, raddr, syslog.Priority(priority), tag)
	if err != nil {
		return nil, ustr.Wrap(err, "ulog")
	}

	return &syslogWriter{writer}, nil
}
