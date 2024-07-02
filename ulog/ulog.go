package ulog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
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
)

type FileOutput struct {
	handle *os.File
	last   time.Time
}
type ULog struct {
	file, console, syslog bool
	fileOutputs           map[string]*FileOutput
	filePath              string
	fileTime              int
	fileLast              time.Time
	fileSeverity          bool
	fileFacility          int
	consoleHandle         io.Writer
	consoleTime           int
	consoleSeverity       bool
	consoleColors         bool
	syslogHandle          *Syslog
	syslogRemote          string
	syslogName            string
	syslogFacility        int
	optionUTC             bool
	level                 int
	fields                map[string]any
	sync.Mutex
	// TODO add compression option
	// TODO add purge option
}

func New(target string) *ULog {
	l := &ULog{
		fileOutputs:  map[string]*FileOutput{},
		syslogHandle: nil,
	}
	return l.Load(target)
}

func (l *ULog) Load(target string) *ULog {
	l.Close()
	l.Lock()
	l.file = false
	l.filePath = ""
	l.fileTime = TIME_DATETIME
	l.fileSeverity = true
	l.console = false
	l.consoleTime = TIME_DATETIME
	l.consoleSeverity = true
	l.consoleColors = true
	l.consoleHandle = os.Stderr
	l.syslog = false
	l.syslogRemote = ""
	l.syslogName = filepath.Base(os.Args[0])
	l.syslogFacility = LOG_DAEMON
	l.optionUTC = false
	l.level = LOG_INFO
	l.fields = map[string]any{}
	console := os.Stderr
	for _, target := range regexp.MustCompile(`(file|console|syslog|option)\s*\(([^\)]*)\)`).FindAllStringSubmatch(target, -1) {
		switch strings.ToLower(target[1]) {
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
						console = os.Stdout
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

	if info, err := console.Stat(); err == nil {
		if info.Mode()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice|os.ModeCharDevice {
			l.consoleColors = false
		}
	}
	if runtime.GOOS == "windows" {
		l.consoleColors = false
	}
	l.Unlock()
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
	l.fields[key] = value
}
func (l *ULog) SetFields(fields map[string]any) {
	for key, value := range fields {
		l.fields[key] = value
	}
}
func (l *ULog) ClearFields() {
	l.fields = map[string]any{}
}

func strftime(layout string, base time.Time) string {
	var out []string

	length := len(layout)
	for index := 0; index < length; index++ {
		switch layout[index] {
		case '%':
			if index < length-1 {
				switch layout[index+1] {
				case 'a':
					out = append(out, base.Format("Mon"))
				case 'A':
					out = append(out, base.Format("Monday"))
				case 'b':
					out = append(out, base.Format("Jan"))
				case 'B':
					out = append(out, base.Format("January"))
				case 'c':
					out = append(out, base.Format("Mon Jan 2 15:04:05 2006"))
				case 'C':
					out = append(out, fmt.Sprintf("%02d", base.Year()/100))
				case 'd':
					out = append(out, fmt.Sprintf("%02d", base.Day()))
				case 'D':
					out = append(out, fmt.Sprintf("%02d/%02d/%02d", base.Month(), base.Day(), base.Year()%100))
				case 'e':
					out = append(out, fmt.Sprintf("%2d", base.Day()))
				case 'f':
					out = append(out, fmt.Sprintf("%06d", base.Nanosecond()/1000))
				case 'F':
					out = append(out, fmt.Sprintf("%04d-%02d-%02d", base.Year(), base.Month(), base.Day()))
				case 'g':
					year, _ := base.ISOWeek()
					out = append(out, fmt.Sprintf("%02d", year%100))
				case 'G':
					year, _ := base.ISOWeek()
					out = append(out, fmt.Sprintf("%04d", year))
				case 'h':
					out = append(out, base.Format("Jan"))
				case 'H':
					out = append(out, fmt.Sprintf("%02d", base.Hour()))
				case 'I':
					if base.Hour() == 0 || base.Hour() == 12 {
						out = append(out, "12")
					} else {
						out = append(out, fmt.Sprintf("%02d", base.Hour()%12))
					}
				case 'j':
					out = append(out, fmt.Sprintf("%03d", base.YearDay()))
				case 'k':
					out = append(out, fmt.Sprintf("%2d", base.Hour()))
				case 'l':
					if base.Hour() == 0 || base.Hour() == 12 {
						out = append(out, "12")
					} else {
						out = append(out, fmt.Sprintf("%2d", base.Hour()%12))
					}
				case 'm':
					out = append(out, fmt.Sprintf("%02d", base.Month()))
				case 'M':
					out = append(out, fmt.Sprintf("%02d", base.Minute()))
				case 'n':
					out = append(out, "\n")
				case 'p':
					if base.Hour() < 12 {
						out = append(out, "AM")
					} else {
						out = append(out, "PM")
					}
				case 'P':
					if base.Hour() < 12 {
						out = append(out, "am")
					} else {
						out = append(out, "pm")
					}
				case 'r':
					if base.Hour() == 0 || base.Hour() == 12 {
						out = append(out, "12")
					} else {
						out = append(out, fmt.Sprintf("%02d", base.Hour()%12))
					}
					out = append(out, fmt.Sprintf(":%02d:%02d", base.Minute(), base.Second()))
					if base.Hour() < 12 {
						out = append(out, " AM")
					} else {
						out = append(out, " PM")
					}
				case 'R':
					out = append(out, fmt.Sprintf("%02d:%02d", base.Hour(), base.Minute()))
				case 's':
					out = append(out, fmt.Sprintf("%d", base.Unix()))
				case 'S':
					out = append(out, fmt.Sprintf("%02d", base.Second()))
				case 't':
					out = append(out, "\t")
				case 'T':
					out = append(out, fmt.Sprintf("%02d:%02d:%02d", base.Hour(), base.Minute(), base.Second()))
				case 'u':
					day := base.Weekday()
					if day == 0 {
						day = 7
					}
					out = append(out, fmt.Sprintf("%d", day))
				case 'U':
					out = append(out, fmt.Sprintf("%d", (base.YearDay()+6-int(base.Weekday()))/7))
				case 'V':
					_, week := base.ISOWeek()
					out = append(out, fmt.Sprintf("%02d", week))
				case 'w':
					out = append(out, fmt.Sprintf("%d", base.Weekday()))
				case 'W':
					day := int(base.Weekday())
					if day == 0 {
						day = 6
					} else {
						day -= 1
					}
					out = append(out, fmt.Sprintf("%d", (base.YearDay()+6-day)/7))
				case 'x':
					out = append(out, fmt.Sprintf("%02d/%02d/%02d", base.Month(), base.Day(), base.Year()%100))
				case 'X':
					out = append(out, fmt.Sprintf("%02d:%02d:%02d", base.Hour(), base.Minute(), base.Second()))
				case 'y':
					out = append(out, fmt.Sprintf("%02d", base.Year()%100))
				case 'Y':
					out = append(out, fmt.Sprintf("%04d", base.Year()))
				case 'z':
					out = append(out, base.Format("-0700"))
				case 'Z':
					out = append(out, base.Format("MST"))
				case '%':
					out = append(out, "%")
				}
				index++
			}
		default:
			out = append(out, string(layout[index]))
		}
	}
	return strings.Join(out, "")
}

func (l *ULog) log(now time.Time, severity int, in any, a ...any) {
	var err error
	if l.level < severity || (!l.syslog && !l.file && !l.console) {
		return
	}
	layout := ""
	if current, ok := in.(map[string]any); ok {
		var buffer bytes.Buffer

		for key, value := range l.fields {
			parts := strings.Split(key, ".")
			for index := 0; index < len(parts)-1; index++ {
				if next, ok := current[parts[index]].(map[string]any); ok {
					current = next
				} else {
					current[parts[index]] = map[string]any{}
					current = current[parts[index]].(map[string]any)
				}
			}
			if current[parts[len(parts)-1]] == nil {
				current[parts[len(parts)-1]] = value
			}
		}
		// TODO add ordered fields
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(in); err == nil {
			layout = "%s"
			a = []any{bytes.TrimSpace(buffer.Bytes())}
		}
	} else if _, ok := in.(string); ok {
		layout = in.(string)
	}
	layout = strings.TrimSpace(layout)
	if l.syslog {
		if l.syslogHandle == nil {
			l.Lock()
			if l.syslogHandle == nil {
				protocol := ""
				if l.syslogRemote != "" {
					protocol = "udp"
				}
				if l.syslogHandle, err = DialSyslog(protocol, l.syslogRemote, l.syslogFacility, l.syslogName); err != nil {
					l.syslogHandle = nil
				}
			}
			l.Unlock()
		}
		if l.syslogHandle != nil {
			switch severity {
			case LOG_ERR:
				l.syslogHandle.Err(fmt.Sprintf(layout, a...))
			case LOG_WARNING:
				l.syslogHandle.Warning(fmt.Sprintf(layout, a...))
			case LOG_INFO:
				l.syslogHandle.Info(fmt.Sprintf(layout, a...))
			case LOG_DEBUG:
				l.syslogHandle.Debug(fmt.Sprintf(layout, a...))
			}
		}
	}
	if l.optionUTC {
		now = now.UTC()
	} else {
		now = now.Local()
	}
	if l.file {
		path := strftime(l.filePath, now)
		l.Lock()
		if l.fileOutputs[path] == nil {
			os.MkdirAll(filepath.Dir(path), 0755)
			if handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0644); err == nil {
				l.fileOutputs[path] = &FileOutput{handle: handle}
			}
		}
		if l.fileOutputs[path] != nil && l.fileOutputs[path].handle != nil {
			prefix := ""
			if l.fileFacility != 0 {
				prefix = fmt.Sprintf("<%d>%s %s[%d]: ", l.fileFacility|severity, now.Format(time.Stamp), l.syslogName, os.Getpid())
			} else {
				switch l.fileTime {
				case TIME_DATETIME:
					prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
				case TIME_MSDATETIME:
					prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/int(time.Millisecond))
				case TIME_TIMESTAMP:
					prefix = fmt.Sprintf("%d ", now.Unix())
				case TIME_MSTIMESTAMP:
					prefix = fmt.Sprintf("%d ", now.UnixNano()/int64(time.Millisecond))
				}
				if l.fileSeverity {
					prefix += severityLabels[severity]
				}
			}
			l.fileOutputs[path].handle.WriteString(fmt.Sprintf(prefix+layout+"\n", a...))
			l.fileOutputs[path].last = now
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
		prefix := ""
		switch l.consoleTime {
		case TIME_DATETIME:
			prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
		case TIME_MSDATETIME:
			prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/int(time.Millisecond))
		case TIME_TIMESTAMP:
			prefix = fmt.Sprintf("%d ", now.Unix())
		case TIME_MSTIMESTAMP:
			prefix = fmt.Sprintf("%d ", now.UnixNano()/int64(time.Millisecond))
		}
		if l.consoleSeverity {
			if l.consoleColors {
				prefix += fmt.Sprintf("%s%s\x1b[0m", severityColors[severity], severityLabels[severity])
			} else {
				prefix += severityLabels[severity]
			}
		}
		l.Lock()
		fmt.Fprintf(l.consoleHandle, prefix+layout+"\n", a...)
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
