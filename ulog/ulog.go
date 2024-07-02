package ulog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/ufmt"
)

const (
	TIME_NONE int = iota
	TIME_DATETIME
	TIME_MSDATETIME
	TIME_TIMESTAMP
	TIME_MSTIMESTAMP
)

const (
	LOG_EMERG int = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

const (
	LOG_KERN int = iota << 3
	LOG_USER
	LOG_MAIL
	LOG_DAEMON
	LOG_AUTH
	LOG_SYSLOG
	LOG_LPR
	LOG_NEWS
	LOG_UUCP
	LOG_CRON
	LOG_AUTHPRIV
	LOG_FTP
	_
	_
	_
	_
	LOG_LOCAL0
	LOG_LOCAL1
	LOG_LOCAL2
	LOG_LOCAL3
	LOG_LOCAL4
	LOG_LOCAL5
	LOG_LOCAL6
	LOG_LOCAL7
)

type FileOutput struct {
	handle *os.File
	last   time.Time
}
type ULog struct {
	syslog, file, console bool
	syslogHandle          *Syslog
	syslogRemote          string
	syslogName            string
	syslogFacility        int
	fileOutputs           map[string]*FileOutput
	filePath              string
	fileTime              int
	fileLast              time.Time
	fileSeverity          bool
	fileFacility          int
	consoleHandle         *os.File
	consoleTime           int
	consoleSeverity       bool
	consoleColors         bool
	optionUTC             bool
	level                 int
	fields                map[string]any
	order                 []string
	external              func(string, []byte)
	sync.RWMutex
	// TODO add compression
	// TODO add purge
}
type colorizer struct {
	expression *regexp.Regexp
	replace    []byte
}

var (
	facilities = map[string]int{
		"user":   LOG_USER,
		"daemon": LOG_DAEMON,
		"local0": LOG_LOCAL0,
		"local1": LOG_LOCAL1,
		"local2": LOG_LOCAL2,
		"local3": LOG_LOCAL3,
		"local4": LOG_LOCAL4,
		"local5": LOG_LOCAL5,
		"local6": LOG_LOCAL6,
		"local7": LOG_LOCAL7,
	}
	severities = map[string]int{
		"error":   LOG_ERR,
		"warning": LOG_WARNING,
		"info":    LOG_INFO,
		"debug":   LOG_DEBUG,
	}
	severityNames = map[int]string{
		LOG_ERR:     "error",
		LOG_WARNING: "warning",
		LOG_INFO:    "info",
		LOG_DEBUG:   "debug",
	}
	severityLabels = map[int]string{
		LOG_ERR:     "ERRO ",
		LOG_WARNING: "WARN ",
		LOG_INFO:    "INFO ",
		LOG_DEBUG:   "DBUG ",
	}
	severityColors = map[int]string{
		LOG_ERR:     "\x1b[31m",
		LOG_WARNING: "\x1b[33m",
		LOG_INFO:    "\x1b[36m",
		LOG_DEBUG:   "\x1b[32m",
	}
	structureColors = []*colorizer{
		&colorizer{regexp.MustCompile(`"(err(:?or)?)":`), []byte("\"\x1b[31m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"(warn(:?ing)?)":`), []byte("\"\x1b[33m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"([^"]+)":`), []byte("\"\x1b[38;5;250m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"([^"]+)"([,}\]])`), []byte("\"\x1b[34m$1\x1b[m\"$2")},
		&colorizer{regexp.MustCompile(`([\-\.\d]+)([,}\]])`), []byte("\x1b[36m$1\x1b[m$2")},
		&colorizer{regexp.MustCompile(`true([,}\]])`), []byte("\x1b[32mtrue\x1b[m$1")},
		&colorizer{regexp.MustCompile(`false([,}\]])`), []byte("\x1b[31mfalse\x1b[m$1")},
		&colorizer{regexp.MustCompile(`null([,}\]])`), []byte("\x1b[35mnull\x1b[m$1")},
	}
)

func New(target string) *ULog {
	l := &ULog{fileOutputs: map[string]*FileOutput{}}
	return l.Load(target)
}

func (l *ULog) Load(target string) *ULog {
	l.Close()
	l.Lock()
	defer l.Unlock()

	l.syslog = false
	l.syslogRemote = ""
	l.syslogName = filepath.Base(os.Args[0])
	l.syslogFacility = LOG_DAEMON
	l.file = false
	l.filePath = ""
	l.fileTime = TIME_DATETIME
	l.fileSeverity = true
	l.console = false
	l.consoleTime = TIME_DATETIME
	l.consoleSeverity = true
	l.consoleColors = true
	l.consoleHandle = os.Stderr
	l.optionUTC = false
	if l.level == 0 {
		l.level = LOG_INFO
	}
	for _, target := range regexp.MustCompile(`(file|console|syslog|option)\s*\(([^\)]*)\)`).FindAllStringSubmatch(target, -1) {
		switch strings.ToLower(target[1]) {
		case "syslog":
			l.syslog = true
			for _, option := range regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`).FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "remote":
					l.syslogRemote = option[2]
					if !regexp.MustCompile(`:\d+$`).MatchString(l.syslogRemote) {
						l.syslogRemote += ":514"
					}
				case "name":
					l.syslogName = option[2]
				case "facility":
					l.syslogFacility = facilities[strings.ToLower(option[2])]
				}
			}

		case "file":
			l.file = true
			for _, option := range regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`).FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "path":
					l.filePath = option[2]

				case "time":
					option[2] = strings.ToLower(option[2])
					switch {
					case option[2] == "datetime":
						l.fileTime = TIME_DATETIME
					case option[2] == "msdatetime":
						l.fileTime = TIME_MSDATETIME
					case option[2] == "stamp" || option[2] == "timestamp":
						l.fileTime = TIME_TIMESTAMP
					case option[2] == "msstamp" || option[2] == "mstimestamp":
						l.fileTime = TIME_MSTIMESTAMP
					case option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes":
						l.fileTime = TIME_NONE
					}

				case "severity":
					option[2] = strings.ToLower(option[2])
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						l.fileSeverity = false
					}

				case "facility":
					l.fileFacility = facilities[strings.ToLower(option[2])]
				}
			}
			if l.filePath == "" {
				l.file = false
			}

		case "console":
			l.console = true
			for _, option := range regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`).FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "output":
					if option[2] == "stdout" {
						l.consoleHandle = os.Stdout
					}

				case "time":
					switch {
					case option[2] == "datetime":
						l.consoleTime = TIME_DATETIME
					case option[2] == "msdatetime":
						l.consoleTime = TIME_MSDATETIME
					case option[2] == "stamp" || option[2] == "timestamp":
						l.consoleTime = TIME_TIMESTAMP
					case option[2] == "msstamp" || option[2] == "mstimestamp":
						l.consoleTime = TIME_MSTIMESTAMP
					case option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes":
						l.consoleTime = TIME_NONE
					}

				case "severity":
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						l.consoleSeverity = false
					}

				case "colors":
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						l.consoleColors = false
					}
				}
			}

		case "option":
			for _, option := range regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`).FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "utc":
					if option[2] == "1" || option[2] == "true" || option[2] == "on" || option[2] == "yes" {
						l.optionUTC = true
					}
				case "level":
					l.level = severities[strings.ToLower(option[2])]
				}
			}
		}
	}

	if l.console {
		if info, err := l.consoleHandle.Stat(); err == nil {
			if info.Mode()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice|os.ModeCharDevice {
				l.consoleColors = false
			}
		}
		if runtime.GOOS == "windows" {
			l.consoleColors = false
		}
	}
	return l
}

func (l *ULog) Close() {
	l.Lock()
	if l.syslogHandle != nil {
		l.syslogHandle.Close()
		l.syslogHandle = nil
	}
	for path, out := range l.fileOutputs {
		if out.handle != nil {
			out.handle.Close()
		}
		delete(l.fileOutputs, path)
	}
	l.Unlock()
}

func (l *ULog) SetLevel(level string) {
	level = strings.ToLower(level)
	switch level {
	case "error":
		l.level = LOG_ERR
	case "warning":
		l.level = LOG_WARNING
	case "info":
		l.level = LOG_INFO
	case "debug":
		l.level = LOG_DEBUG
	}
}

func (l *ULog) SetField(key string, value any) {
	l.Lock()
	if l.fields == nil {
		l.fields = map[string]any{}
	}
	l.fields[key] = value
	l.Unlock()
}
func (l *ULog) SetFields(fields map[string]any) {
	for key, value := range fields {
		l.SetField(key, value)
	}
}
func (l *ULog) ClearFields() {
	l.Lock()
	l.fields = nil
	l.Unlock()
}

func (l *ULog) SetOrder(names []string) {
	l.Lock()
	l.order = names
	l.Unlock()
}
func (l *ULog) ClearOrder() {
	l.Lock()
	l.order = nil
	l.Unlock()
}

func (l *ULog) SetExternal(external func(string, []byte)) {
	l.Lock()
	l.external = external
	l.Unlock()
}
func (l *ULog) ClearExternal() {
	l.Lock()
	l.external = nil
	l.Unlock()
}

func (l *ULog) log(now time.Time, severity int, in any, a ...any) {
	l.RLock()
	if l.level < severity || (!l.syslog && l.external == nil && !l.file && !l.console) {
		l.RUnlock()
		return
	}
	l.RUnlock()

	structured, content := false, bslab.Get(1<<8, nil)
	defer bslab.Put(content)

	if structure, ok := in.(map[string]any); ok {
		structured = true
		l.RLock()
		for key, value := range l.fields {
			if _, exists := structure[key]; !exists {
				structure[key] = value
			}
		}

		buffer := bytes.NewBuffer([]byte{'{'})
		if len(structure) != 0 {
			encoder := json.NewEncoder(buffer)
			encoder.SetEscapeHTML(false)
			for _, key := range l.order {
				if _, exists := structure[key]; exists {
					buffer.WriteString(`"` + key + `":`)
					encoder.Encode(structure[key])
					buffer.Truncate(buffer.Len() - 1)
					buffer.WriteByte(',')
				}
			}
			for _, key := range ufmt.Keys(structure) {
				if !slices.Contains(l.order, key) {
					buffer.WriteString(`"` + key + `":`)
					encoder.Encode(structure[key])
					buffer.Truncate(buffer.Len() - 1)
					buffer.WriteByte(',')
				}
			}
			buffer.Truncate(buffer.Len() - 1)
		}
		l.RUnlock()
		buffer.WriteByte('}')
		content = append(content, buffer.Bytes()...)

	} else if layout, ok := in.(string); ok {
		content = fmt.Appendf(content, strings.TrimSpace(layout), a...)
	}

	if l.syslog {
		if l.syslogHandle == nil {
			l.Lock()
			if l.syslogHandle == nil {
				protocol := ""
				if l.syslogRemote != "" {
					protocol = "udp"
				}
				if handle, err := DialSyslog(protocol, l.syslogRemote, l.syslogFacility, l.syslogName); err == nil {
					l.syslogHandle = handle
				}
			}
			l.Unlock()
		}
		if l.syslogHandle != nil {
			switch severity {
			case LOG_ERR:
				l.syslogHandle.Err(string(content))
			case LOG_WARNING:
				l.syslogHandle.Warning(string(content))
			case LOG_INFO:
				l.syslogHandle.Info(string(content))
			case LOG_DEBUG:
				l.syslogHandle.Debug(string(content))
			}
		}
	}

	l.RLock()
	if l.external != nil {
		l.external(severityNames[severity], content)
	}
	l.RUnlock()

	content = append(content, '\n')
	if l.optionUTC {
		now = now.UTC()
	} else {
		now = now.Local()
	}
	if l.file {
		path := ufmt.Strftime(l.filePath, now)
		l.Lock()
		if _, exists := l.fileOutputs[path]; !exists {
			os.MkdirAll(filepath.Dir(path), 0755)
			if handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0644); err == nil {
				l.fileOutputs[path] = &FileOutput{handle: handle}
			}
		}
		if output, exists := l.fileOutputs[path]; exists {
			if handle := output.handle; handle != nil {
				prefix := make([]byte, 0, 128)
				if l.fileFacility != 0 {
					prefix = append(prefix, '<')
					prefix = append(prefix, strconv.Itoa(l.fileFacility|severity)...)
					prefix = append(prefix, '>')
					prefix = append(prefix, now.Format(time.Stamp)...)
					prefix = append(prefix, ' ')
					prefix = append(prefix, l.syslogName...)
					prefix = append(prefix, '[')
					prefix = append(prefix, strconv.Itoa(os.Getpid())...)
					prefix = append(prefix, []byte{']', ':', ' '}...)
				} else {
					switch l.fileTime {
					case TIME_DATETIME:
						prefix = append(prefix, now.Format(time.DateTime)...)
					case TIME_MSDATETIME:
						prefix = append(prefix, now.Format(time.DateTime+".000")...)
					case TIME_TIMESTAMP:
						prefix = append(prefix, strconv.FormatInt(now.Unix(), 10)...)
					case TIME_MSTIMESTAMP:
						prefix = append(prefix, strconv.FormatInt(now.UnixNano()/int64(time.Millisecond), 10)...)
					}
					if len(prefix) != 0 {
						prefix = append(prefix, ' ')
					}
					if l.fileSeverity {
						prefix = append(prefix, severityLabels[severity]...)
					}
				}
				handle.Write(prefix)
				handle.Write(content)
				l.fileOutputs[path].last = now
			}
		}
		if now.Sub(l.fileLast) >= 5*time.Second {
			l.fileLast = now
			for path, out := range l.fileOutputs {
				if now.Sub(out.last) >= 5*time.Second {
					out.handle.Close()
					delete(l.fileOutputs, path)
				}
			}
		}
		l.Unlock()
	}

	if l.console {
		prefix := make([]byte, 0, 128)
		if l.consoleTime != TIME_NONE {
			if l.consoleColors {
				prefix = append(prefix, "\x1b[38;5;250m"...)
			}
			switch l.consoleTime {
			case TIME_DATETIME:
				prefix = append(prefix, now.Format(time.DateTime)...)
			case TIME_MSDATETIME:
				prefix = append(prefix, now.Format(time.DateTime+".000")...)
			case TIME_TIMESTAMP:
				prefix = append(prefix, strconv.FormatInt(now.Unix(), 10)...)
			case TIME_MSTIMESTAMP:
				prefix = append(prefix, strconv.FormatInt(now.UnixNano()/int64(time.Millisecond), 10)...)
			}
			if l.consoleColors {
				prefix = append(prefix, "\x1b[m"...)
			}
			prefix = append(prefix, ' ')
		}
		if l.consoleSeverity {
			if l.consoleColors {
				prefix = append(prefix, severityColors[severity]...)
			}
			prefix = append(prefix, severityLabels[severity]...)
			if l.consoleColors {
				prefix = append(prefix, "\x1b[m"...)
			}
		}
		if structured && l.consoleColors {
			for _, item := range structureColors {
				content = item.expression.ReplaceAll(content, item.replace)
			}
		}
		l.Lock()
		l.consoleHandle.Write(prefix)
		l.consoleHandle.Write(content)
		l.Unlock()
	}
}

func (l *ULog) Error(layout any, a ...any) {
	l.log(time.Now(), LOG_ERR, layout, a...)
}
func (l *ULog) Warn(layout any, a ...any) {
	l.log(time.Now(), LOG_WARNING, layout, a...)
}
func (l *ULog) Info(layout any, a ...any) {
	l.log(time.Now(), LOG_INFO, layout, a...)
}
func (l *ULog) Debug(layout any, a ...any) {
	l.log(time.Now(), LOG_DEBUG, layout, a...)
}

func (l *ULog) ErrorTime(now time.Time, layout any, a ...any) {
	l.log(now, LOG_ERR, layout, a...)
}
func (l *ULog) WarnTime(now time.Time, layout any, a ...any) {
	l.log(now, LOG_WARNING, layout, a...)
}
func (l *ULog) InfoTime(now time.Time, layout any, a ...any) {
	l.log(now, LOG_INFO, layout, a...)
}
func (l *ULog) DebugTime(now time.Time, layout any, a ...any) {
	l.log(now, LOG_DEBUG, layout, a...)
}
