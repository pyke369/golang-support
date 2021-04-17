package ulog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	sync.Mutex
}

func New(target string) *ULog {
	log := &ULog{
		fileOutputs:  map[string]*FileOutput{},
		syslogHandle: nil,
	}
	return log.Load(target)
}

func (this *ULog) Load(target string) *ULog {
	this.Close()
	this.Lock()
	this.file = false
	this.filePath = ""
	this.fileTime = TIME_DATETIME
	this.fileSeverity = true
	this.console = false
	this.consoleTime = TIME_DATETIME
	this.consoleSeverity = true
	this.consoleColors = true
	this.consoleHandle = os.Stderr
	this.syslog = false
	this.syslogRemote = ""
	this.syslogName = filepath.Base(os.Args[0])
	this.syslogFacility = LOG_DAEMON
	this.optionUTC = false
	this.level = LOG_INFO
	console := os.Stderr
	for _, target := range regexp.MustCompile("(file|console|syslog|option)\\s*\\(([^\\)]*)\\)").FindAllStringSubmatch(target, -1) {
		switch strings.ToLower(target[1]) {
		case "file":
			this.file = true
			for _, option := range regexp.MustCompile("([^:=,\\s]+)\\s*[:=]\\s*([^,\\s]+)").FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "path":
					this.filePath = option[2]
				case "time":
					option[2] = strings.ToLower(option[2])
					switch {
					case option[2] == "datetime":
						this.fileTime = TIME_DATETIME
					case option[2] == "msdatetime":
						this.fileTime = TIME_MSDATETIME
					case option[2] == "stamp" || option[2] == "timestamp":
						this.fileTime = TIME_TIMESTAMP
					case option[2] == "msstamp" || option[2] == "mstimestamp":
						this.fileTime = TIME_MSTIMESTAMP
					case option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes":
						this.fileTime = TIME_NONE
					}
				case "severity":
					option[2] = strings.ToLower(option[2])
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						this.fileSeverity = false
					}
				case "facility":
					this.fileFacility = facilities[strings.ToLower(option[2])]
				}
			}
			if this.filePath == "" {
				this.file = false
			}
		case "console":
			this.console = true
			for _, option := range regexp.MustCompile("([^:=,\\s]+)\\s*[:=]\\s*([^,\\s]+)").FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "output":
					if option[2] == "stdout" {
						this.consoleHandle = os.Stdout
						console = os.Stdout
					}
				case "time":
					switch {
					case option[2] == "datetime":
						this.consoleTime = TIME_DATETIME
					case option[2] == "msdatetime":
						this.consoleTime = TIME_MSDATETIME
					case option[2] == "stamp" || option[2] == "timestamp":
						this.consoleTime = TIME_TIMESTAMP
					case option[2] == "msstamp" || option[2] == "mstimestamp":
						this.consoleTime = TIME_MSTIMESTAMP
					case option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes":
						this.consoleTime = TIME_NONE
					}
				case "severity":
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						this.consoleSeverity = false
					}
				case "colors":
					if option[2] != "1" && option[2] != "true" && option[2] != "on" && option[2] != "yes" {
						this.consoleColors = false
					}
				}
			}
		case "syslog":
			this.syslog = true
			for _, option := range regexp.MustCompile("([^:=,\\s]+)\\s*[:=]\\s*([^,\\s]+)").FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "remote":
					this.syslogRemote = option[2]
					if !regexp.MustCompile(":\\d+$").MatchString(this.syslogRemote) {
						this.syslogRemote += ":514"
					}
				case "name":
					this.syslogName = option[2]
				case "facility":
					this.syslogFacility = facilities[strings.ToLower(option[2])]
				}
			}
		case "option":
			for _, option := range regexp.MustCompile("([^:=,\\s]+)\\s*[:=]\\s*([^,\\s]+)").FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "utc":
					if option[2] == "1" || option[2] == "true" || option[2] == "on" || option[2] == "yes" {
						this.optionUTC = true
					}
				case "level":
					this.level = severities[strings.ToLower(option[2])]
				}
			}
		}
	}

	if info, err := console.Stat(); err == nil {
		if info.Mode()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice|os.ModeCharDevice {
			this.consoleColors = false
		}
	}
	if runtime.GOOS == "windows" {
		this.consoleColors = false
	}
	this.Unlock()
	return this
}

func (this *ULog) Close() {
	this.Lock()
	if this.syslogHandle != nil {
		this.syslogHandle.Close()
		this.syslogHandle = nil
	}
	for path, output := range this.fileOutputs {
		if output.handle != nil {
			output.handle.Close()
		}
		delete(this.fileOutputs, path)
	}
	this.Unlock()
}

func (this *ULog) SetLevel(level string) {
	level = strings.ToLower(level)
	switch level {
	case "error":
		this.level = LOG_ERR
	case "warning":
		this.level = LOG_WARNING
	case "info":
		this.level = LOG_INFO
	case "debug":
		this.level = LOG_DEBUG
	}
}

func strftime(layout string, base time.Time) string {
	var output []string

	length := len(layout)
	for index := 0; index < length; index++ {
		switch layout[index] {
		case '%':
			if index < length-1 {
				switch layout[index+1] {
				case 'a':
					output = append(output, base.Format("Mon"))
				case 'A':
					output = append(output, base.Format("Monday"))
				case 'b':
					output = append(output, base.Format("Jan"))
				case 'B':
					output = append(output, base.Format("January"))
				case 'c':
					output = append(output, base.Format("Mon Jan 2 15:04:05 2006"))
				case 'C':
					output = append(output, fmt.Sprintf("%02d", base.Year()/100))
				case 'd':
					output = append(output, fmt.Sprintf("%02d", base.Day()))
				case 'D':
					output = append(output, fmt.Sprintf("%02d/%02d/%02d", base.Month(), base.Day(), base.Year()%100))
				case 'e':
					output = append(output, fmt.Sprintf("%2d", base.Day()))
				case 'f':
					output = append(output, fmt.Sprintf("%06d", base.Nanosecond()/1000))
				case 'F':
					output = append(output, fmt.Sprintf("%04d-%02d-%02d", base.Year(), base.Month(), base.Day()))
				case 'g':
					year, _ := base.ISOWeek()
					output = append(output, fmt.Sprintf("%02d", year%100))
				case 'G':
					year, _ := base.ISOWeek()
					output = append(output, fmt.Sprintf("%04d", year))
				case 'h':
					output = append(output, base.Format("Jan"))
				case 'H':
					output = append(output, fmt.Sprintf("%02d", base.Hour()))
				case 'I':
					if base.Hour() == 0 || base.Hour() == 12 {
						output = append(output, "12")
					} else {
						output = append(output, fmt.Sprintf("%02d", base.Hour()%12))
					}
				case 'j':
					output = append(output, fmt.Sprintf("%03d", base.YearDay()))
				case 'k':
					output = append(output, fmt.Sprintf("%2d", base.Hour()))
				case 'l':
					if base.Hour() == 0 || base.Hour() == 12 {
						output = append(output, "12")
					} else {
						output = append(output, fmt.Sprintf("%2d", base.Hour()%12))
					}
				case 'm':
					output = append(output, fmt.Sprintf("%02d", base.Month()))
				case 'M':
					output = append(output, fmt.Sprintf("%02d", base.Minute()))
				case 'n':
					output = append(output, "\n")
				case 'p':
					if base.Hour() < 12 {
						output = append(output, "AM")
					} else {
						output = append(output, "PM")
					}
				case 'P':
					if base.Hour() < 12 {
						output = append(output, "am")
					} else {
						output = append(output, "pm")
					}
				case 'r':
					if base.Hour() == 0 || base.Hour() == 12 {
						output = append(output, "12")
					} else {
						output = append(output, fmt.Sprintf("%02d", base.Hour()%12))
					}
					output = append(output, fmt.Sprintf(":%02d:%02d", base.Minute(), base.Second()))
					if base.Hour() < 12 {
						output = append(output, " AM")
					} else {
						output = append(output, " PM")
					}
				case 'R':
					output = append(output, fmt.Sprintf("%02d:%02d", base.Hour(), base.Minute()))
				case 's':
					output = append(output, fmt.Sprintf("%d", base.Unix()))
				case 'S':
					output = append(output, fmt.Sprintf("%02d", base.Second()))
				case 't':
					output = append(output, "\t")
				case 'T':
					output = append(output, fmt.Sprintf("%02d:%02d:%02d", base.Hour(), base.Minute(), base.Second()))
				case 'u':
					day := base.Weekday()
					if day == 0 {
						day = 7
					}
					output = append(output, fmt.Sprintf("%d", day))
				case 'U':
					output = append(output, fmt.Sprintf("%d", (base.YearDay()+6-int(base.Weekday()))/7))
				case 'V':
					_, week := base.ISOWeek()
					output = append(output, fmt.Sprintf("%02d", week))
				case 'w':
					output = append(output, fmt.Sprintf("%d", base.Weekday()))
				case 'W':
					day := int(base.Weekday())
					if day == 0 {
						day = 6
					} else {
						day -= 1
					}
					output = append(output, fmt.Sprintf("%d", (base.YearDay()+6-day)/7))
				case 'x':
					output = append(output, fmt.Sprintf("%02d/%02d/%02d", base.Month(), base.Day(), base.Year()%100))
				case 'X':
					output = append(output, fmt.Sprintf("%02d:%02d:%02d", base.Hour(), base.Minute(), base.Second()))
				case 'y':
					output = append(output, fmt.Sprintf("%02d", base.Year()%100))
				case 'Y':
					output = append(output, fmt.Sprintf("%04d", base.Year()))
				case 'z':
					output = append(output, base.Format("-0700"))
				case 'Z':
					output = append(output, base.Format("MST"))
				case '%':
					output = append(output, "%")
				}
				index++
			}
		default:
			output = append(output, string(layout[index]))
		}
	}
	return strings.Join(output, "")
}

func (this *ULog) log(now time.Time, severity int, xlayout interface{}, a ...interface{}) {
	var err error
	if this.level < severity || (!this.syslog && !this.file && !this.console) {
		return
	}
	layout := ""
	switch reflect.TypeOf(xlayout).Kind() {
	case reflect.Map:
		var buffer bytes.Buffer

		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(xlayout); err == nil {
			layout = "%s"
			a = []interface{}{bytes.TrimSpace(buffer.Bytes())}
		}
	case reflect.String:
		layout = xlayout.(string)
	}
	layout = strings.TrimSpace(layout)
	if this.syslog {
		if this.syslogHandle == nil {
			this.Lock()
			if this.syslogHandle == nil {
				protocol := ""
				if this.syslogRemote != "" {
					protocol = "udp"
				}
				if this.syslogHandle, err = DialSyslog(protocol, this.syslogRemote, this.syslogFacility, this.syslogName); err != nil {
					this.syslogHandle = nil
				}
			}
			this.Unlock()
		}
		if this.syslogHandle != nil {
			switch severity {
			case LOG_ERR:
				this.syslogHandle.Err(fmt.Sprintf(layout, a...))
			case LOG_WARNING:
				this.syslogHandle.Warning(fmt.Sprintf(layout, a...))
			case LOG_INFO:
				this.syslogHandle.Info(fmt.Sprintf(layout, a...))
			case LOG_DEBUG:
				this.syslogHandle.Debug(fmt.Sprintf(layout, a...))
			}
		}
	}
	if this.optionUTC {
		now = now.UTC()
	} else {
		now = now.Local()
	}
	if this.file {
		path := strftime(this.filePath, now)
		this.Lock()
		if this.fileOutputs[path] == nil {
			os.MkdirAll(filepath.Dir(path), 0755)
			if handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0644); err == nil {
				this.fileOutputs[path] = &FileOutput{handle: handle}
			}
		}
		if this.fileOutputs[path] != nil && this.fileOutputs[path].handle != nil {
			prefix := ""
			if this.fileFacility != 0 {
				prefix = fmt.Sprintf("<%d>%s %s[%d]: ", this.fileFacility|severity, now.Format(time.Stamp), this.syslogName, os.Getpid())
			} else {
				switch this.fileTime {
				case TIME_DATETIME:
					prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
				case TIME_MSDATETIME:
					prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/int(time.Millisecond))
				case TIME_TIMESTAMP:
					prefix = fmt.Sprintf("%d ", now.Unix())
				case TIME_MSTIMESTAMP:
					prefix = fmt.Sprintf("%d ", now.UnixNano()/int64(time.Millisecond))
				}
				if this.fileSeverity {
					prefix += severityLabels[severity]
				}
			}
			this.fileOutputs[path].handle.WriteString(fmt.Sprintf(prefix+layout+"\n", a...))
			this.fileOutputs[path].last = now
		}
		if now.Sub(this.fileLast) >= 5*time.Second {
			this.fileLast = now
			for path, output := range this.fileOutputs {
				if now.Sub(output.last) >= 5*time.Second {
					output.handle.Close()
					delete(this.fileOutputs, path)
				}
			}
		}
		this.Unlock()
	}
	if this.console {
		prefix := ""
		switch this.consoleTime {
		case TIME_DATETIME:
			prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
		case TIME_MSDATETIME:
			prefix = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d ", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/int(time.Millisecond))
		case TIME_TIMESTAMP:
			prefix = fmt.Sprintf("%d ", now.Unix())
		case TIME_MSTIMESTAMP:
			prefix = fmt.Sprintf("%d ", now.UnixNano()/int64(time.Millisecond))
		}
		if this.consoleSeverity {
			if this.consoleColors {
				prefix += fmt.Sprintf("%s%s\x1b[0m", severityColors[severity], severityLabels[severity])
			} else {
				prefix += severityLabels[severity]
			}
		}
		this.Lock()
		fmt.Fprintf(this.consoleHandle, prefix+layout+"\n", a...)
		this.Unlock()
	}
}

func (this *ULog) Error(layout interface{}, a ...interface{}) {
	this.log(time.Now(), LOG_ERR, layout, a...)
}
func (this *ULog) Warn(layout interface{}, a ...interface{}) {
	this.log(time.Now(), LOG_WARNING, layout, a...)
}
func (this *ULog) Info(layout interface{}, a ...interface{}) {
	this.log(time.Now(), LOG_INFO, layout, a...)
}
func (this *ULog) Debug(layout interface{}, a ...interface{}) {
	this.log(time.Now(), LOG_DEBUG, layout, a...)
}

func (this *ULog) ErrorTime(now time.Time, layout interface{}, a ...interface{}) {
	this.log(now, LOG_ERR, layout, a...)
}
func (this *ULog) WarnTime(now time.Time, layout interface{}, a ...interface{}) {
	this.log(now, LOG_WARNING, layout, a...)
}
func (this *ULog) InfoTime(now time.Time, layout interface{}, a ...interface{}) {
	this.log(now, LOG_INFO, layout, a...)
}
func (this *ULog) DebugTime(now time.Time, layout interface{}, a ...interface{}) {
	this.log(now, LOG_DEBUG, layout, a...)
}
