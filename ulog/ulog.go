package ulog

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/bslab"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/ustr"
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

type ULog struct {
	syslog, file, console bool
	syslogHandle          *syslogWriter
	syslogRemote          string
	syslogName            string
	syslogFacility        int
	fileOutputs           map[string]*fileOutput
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
	purgePath             string
	purgeAge              time.Duration
	purgeCount            int
	compressPath          string
	compressAge           time.Duration
	level                 int
	fields                map[string]any
	order                 []string
	external              func(string, []byte)
	mu                    sync.RWMutex
}
type fileOutput struct {
	handle *os.File
	last   time.Time
	path   string
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
		&colorizer{regexp.MustCompile(`([\-.\d]+)([,}\]])`), []byte("\x1b[36m$1\x1b[m$2")},
		&colorizer{regexp.MustCompile(`true([,}\]])`), []byte("\x1b[32mtrue\x1b[m$1")},
		&colorizer{regexp.MustCompile(`false([,}\]])`), []byte("\x1b[33mfalse\x1b[m$1")},
		&colorizer{regexp.MustCompile(`null([,}\]])`), []byte("\x1b[35mnull\x1b[m$1")},
	}
	optionParser   = regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`)
	templateParser = regexp.MustCompile(`\{\{\s*[^\s\}]+\s*\}\}`)
)

func New(target string) *ULog {
	l := &ULog{fileOutputs: map[string]*fileOutput{}, level: LOG_INFO}

	go func(l *ULog) {
		time.Sleep(time.Second)
		for {
			go func() {
				l.mu.RLock()
				if l.purgePath != "" && (l.purgeAge > 0 || l.purgeCount > 0) {
					go func() {
						if paths, err := filepath.Glob(l.purgePath); err == nil {
							entries := []*fileOutput{}
							for _, path := range paths {
								if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
									entries = append(entries, &fileOutput{last: info.ModTime(), path: path})
								}
							}
							sort.Slice(entries, func(i, j int) bool {
								return entries[i].last.After(entries[j].last)
							})
							for index, entry := range entries {
								if l.purgeAge > 0 && time.Since(entry.last) >= l.purgeAge {
									os.Remove(entry.path)
									os.Remove(filepath.Dir(entry.path))
								}
								if l.purgeCount > 0 && index >= l.purgeCount {
									os.Remove(entry.path)
									os.Remove(filepath.Dir(entry.path))
								}
							}
						}
					}()
				}
				if l.compressPath != "" && l.compressAge > 0 {
					go func() {
						if paths, err := filepath.Glob(l.compressPath); err == nil {
							start := time.Now()
							for _, path := range paths {
								if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) >= l.compressAge {
									ok := false
									if source, err := os.Open(path); err == nil {
										if target, err := os.OpenFile(path+".gz", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644); err == nil {
											gzwriter := gzip.NewWriter(target)
											_, err := io.Copy(gzwriter, source)
											gzwriter.Close()
											target.Close()
											if err == nil {
												if err := os.Chtimes(path+".gz", time.Time{}, info.ModTime()); err == nil {
													ok = true
												}
											}
										}
										source.Close()
									}
									if ok {
										os.Remove(path)
									} else {
										os.Remove(path + ".gz")
									}
								}
								if time.Since(start) >= 5*time.Minute {
									break
								}
							}
						}
					}()
				}
				l.mu.RUnlock()
			}()
			time.Sleep(10 * time.Minute)
		}
	}(l)

	return l.Load(target)
}

func (l *ULog) Load(target string) *ULog {
	l.Close()

	l.mu.Lock()
	defer l.mu.Unlock()
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
	l.purgePath = ""
	l.purgeAge = 0
	l.purgeCount = 0
	l.compressPath = ""
	l.compressAge = 0

	for _, target := range regexp.MustCompile(`(file|console|syslog|option|purge|compress)\s*\(([^\)]*)\)`).FindAllStringSubmatch(target, -1) {
		switch strings.ToLower(target[1]) {
		case "syslog":
			l.syslog = true
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "remote":
					l.syslogRemote = option[2]
					if _, _, err := net.SplitHostPort(l.syslogRemote); err != nil {
						l.syslogRemote += ":514"
					}

				case "name":
					l.syslogName = option[2]

				case "facility":
					l.syslogFacility = facilities[strings.ToLower(option[2])]
				}
			}

		case "file":
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "path":
					l.filePath, l.file = option[2], true

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
					case !j.Boolean(option[2]):
						l.fileTime = TIME_NONE
					}

				case "severity":
					l.fileSeverity = j.Boolean(option[2])

				case "facility":
					l.fileFacility = facilities[strings.ToLower(option[2])]
				}
			}

		case "console":
			l.console = true
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
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
					case !j.Boolean(option[2]):
						l.consoleTime = TIME_NONE
					}

				case "severity":
					l.consoleSeverity = j.Boolean(option[2])

				case "colors":
					l.consoleColors = j.Boolean(option[2])
				}
			}

		case "option":
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "utc":
					l.optionUTC = j.Boolean(option[2])

				case "level":
					l.level = severities[option[2]]
				}
			}

		case "purge":
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "path":
					l.purgePath = strings.TrimSpace(option[2])

				case "age":
					l.purgeAge = j.Duration(option[2], 0)
					if l.purgeAge != 0 {
						l.purgeAge = max(10*time.Minute, l.purgeAge)
					}

				case "count":
					if value, err := strconv.Atoi(option[2]); err == nil {
						l.purgeCount = max(0, value)
					}
				}
			}

		case "compress":
			for _, option := range optionParser.FindAllStringSubmatch(target[2], -1) {
				switch strings.ToLower(option[1]) {
				case "path":
					l.compressPath = strings.TrimSpace(option[2])

				case "age":
					l.compressAge = j.Duration(option[2], 0)
					if l.compressAge != 0 {
						l.compressAge = max(10*time.Minute, l.compressAge)
					}
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
	l.mu.Lock()
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
	l.mu.Unlock()
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
	l.mu.Lock()
	if l.fields == nil {
		l.fields = map[string]any{}
	}
	l.fields[key] = value
	l.mu.Unlock()
}
func (l *ULog) SetFields(fields map[string]any) {
	for key, value := range fields {
		l.SetField(key, value)
	}
}
func (l *ULog) ClearFields() {
	l.mu.Lock()
	l.fields = nil
	l.mu.Unlock()
}

func (l *ULog) SetOrder(names []string) {
	l.mu.Lock()
	l.order = names
	l.mu.Unlock()
}
func (l *ULog) ClearOrder() {
	l.mu.Lock()
	l.order = nil
	l.mu.Unlock()
}

func (l *ULog) SetExternal(external func(string, []byte)) {
	l.mu.Lock()
	l.external = external
	l.mu.Unlock()
}
func (l *ULog) ClearExternal() {
	l.mu.Lock()
	l.external = nil
	l.mu.Unlock()
}

func (l *ULog) Log(now time.Time, severity int, in any, a ...any) {
	l.mu.RLock()
	if l.level < severity || (!l.syslog && l.external == nil && !l.file && !l.console) {
		l.mu.RUnlock()
		return
	}
	l.mu.RUnlock()

	structured, content := false, bslab.Get(1<<10, nil)
	defer bslab.Put(content)

	templates := map[string]any{
		"datetime":    now.Format(time.DateTime),
		"msdatetime":  now.Format(time.DateTime + ".000"),
		"timestamp":   now.Unix(),
		"mstimestamp": now.UnixNano() / int64(time.Millisecond),
	}
	if structure, ok := in.(map[string]any); ok {
		structured = true
		l.mu.RLock()
		for key, value := range l.fields {
			if _, exists := structure[key]; !exists {
				structure[key] = value
			}
		}
		for key, value := range structure {
			key = strings.TrimSpace(key)
			if strings.HasPrefix(key, "{{") && strings.HasSuffix(key, "}}") {
				delete(structure, key)
				key = strings.ToLower(strings.TrimSpace(key[2 : len(key)-2]))
				templates[key] = value
			}
		}
		for key, value := range structure {
			if value, ok := value.(string); ok {
				if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
					value = strings.ToLower(strings.TrimSpace(value[2 : len(value)-2]))
					if value, ok := templates[value]; ok {
						structure[key] = value
					} else {
						delete(structure, key)
					}
				}
			}
		}

		if value, ok := templates["payload"].(string); ok {
			content = append(content, value...)

		} else {
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
				for _, key := range j.MapKeys(structure) {
					if !slices.Contains(l.order, key) {
						buffer.WriteString(`"` + key + `":`)
						encoder.Encode(structure[key])
						buffer.Truncate(buffer.Len() - 1)
						buffer.WriteByte(',')
					}
				}
				buffer.Truncate(buffer.Len() - 1)
			}
			buffer.WriteByte('}')
			content = append(content, buffer.Bytes()...)
		}
		l.mu.RUnlock()
	}

	if layout, ok := in.(string); ok {
		content = fmt.Appendf(content, strings.TrimSpace(layout), a...)
	}

	if l.syslog {
		l.mu.Lock()
		if l.syslogHandle == nil {
			protocol := ""
			if l.syslogRemote != "" {
				protocol = "udp"
			}
			if handle, err := dialSyslog(protocol, l.syslogRemote, l.syslogFacility, l.syslogName); err == nil {
				l.syslogHandle = handle
			}
		}
		l.mu.Unlock()
		l.mu.RLock()
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
		l.mu.RUnlock()
	}

	l.mu.RLock()
	if l.external != nil {
		l.external(severityNames[severity], content)
	}
	l.mu.RUnlock()

	content = append(content, '\n')
	if l.optionUTC {
		now = now.UTC()
	} else {
		now = now.Local()
	}
	if l.file {
		path := ustr.Strftime(l.filePath, now)
		if structured {
			path = templateParser.ReplaceAllStringFunc(path, func(key string) string {
				key = strings.ToLower(strings.TrimSpace(key[2 : len(key)-2]))
				if value, ok := templates[key]; ok {
					if value, ok := value.(string); ok {
						return value
					}
				}
				return ""
			})
		}

		l.mu.Lock()
		if _, exists := l.fileOutputs[path]; !exists {
			os.MkdirAll(filepath.Dir(path), 0o755)
			if handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0o644); err == nil {
				l.fileOutputs[path] = &fileOutput{handle: handle}
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
		if now.Sub(l.fileLast) >= time.Minute {
			l.fileLast = now
			for path, out := range l.fileOutputs {
				if now.Sub(out.last) >= time.Minute {
					out.handle.Close()
					delete(l.fileOutputs, path)
				}
			}
		}
		l.mu.Unlock()
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
		l.mu.Lock()
		l.consoleHandle.Write(prefix)
		l.consoleHandle.Write(content)
		l.mu.Unlock()
	}
}

func (l *ULog) Error(layout any, a ...any) {
	l.Log(time.Now(), LOG_ERR, layout, a...)
}
func (l *ULog) Warn(layout any, a ...any) {
	l.Log(time.Now(), LOG_WARNING, layout, a...)
}
func (l *ULog) Info(layout any, a ...any) {
	l.Log(time.Now(), LOG_INFO, layout, a...)
}
func (l *ULog) Debug(layout any, a ...any) {
	l.Log(time.Now(), LOG_DEBUG, layout, a...)
}

func (l *ULog) ErrorTime(now time.Time, layout any, a ...any) {
	l.Log(now, LOG_ERR, layout, a...)
}
func (l *ULog) WarnTime(now time.Time, layout any, a ...any) {
	l.Log(now, LOG_WARNING, layout, a...)
}
func (l *ULog) InfoTime(now time.Time, layout any, a ...any) {
	l.Log(now, LOG_INFO, layout, a...)
}
func (l *ULog) DebugTime(now time.Time, layout any, a ...any) {
	l.Log(now, LOG_DEBUG, layout, a...)
}
