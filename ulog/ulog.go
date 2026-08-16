package ulog

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"encoding/json"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/file"
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
	root                  string
	syslog, file, console bool
	syslogHandle          *syslogWriter
	syslogRemote          string
	syslogName            string
	syslogFacility        int
	fileOutputs           map[string]*list.Element
	filePath              string
	fileTime              int
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
	arena                 *bslab.Arena
	mu                    sync.RWMutex
	done                  chan struct{}
	lru                   *list.List
}

type fileOutput struct {
	path   string
	active time.Time
	handle *os.File
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
		&colorizer{regexp.MustCompile(`"(err(:?or)?|reason)":`), []byte("\"\x1b[31m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"(warn(:?ing)?)":`), []byte("\"\x1b[33m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"([^"]+)":`), []byte("\"\x1b[38;5;250m$1\x1b[m\":")},
		&colorizer{regexp.MustCompile(`"([^"]+)"([,}\]])`), []byte("\"\x1b[34m$1\x1b[m\"$2")},
		&colorizer{regexp.MustCompile(`([\-.\d]+)([,}\]])`), []byte("\x1b[36m$1\x1b[m$2")},
		&colorizer{regexp.MustCompile(`true([,}\]])`), []byte("\x1b[32mtrue\x1b[m$1")},
		&colorizer{regexp.MustCompile(`false([,}\]])`), []byte("\x1b[33mfalse\x1b[m$1")},
		&colorizer{regexp.MustCompile(`null([,}\]])`), []byte("\x1b[35mnull\x1b[m$1")},
	}
	optionMatcher   = regexp.MustCompile(`([^:=,\s]+)\s*[:=]\s*([^,\s]+)`)
	templateMatcher = regexp.MustCompile(`\{\{\s*[^\s\}]+\s*\}\}`)
)

func New(target string, root string, arena ...*bslab.Arena) *ULog {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		if value, err := filepath.Abs(root); err == nil {
			root = value
		}
	}
	l := &ULog{root: root, fileOutputs: map[string]*list.Element{}, level: LOG_INFO, arena: bslab.Default, lru: list.New()}
	if len(arena) != 0 && arena[0] != nil {
		l.arena = arena[0]
	}

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
	l.fileFacility = 0
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
	l.level = LOG_INFO
	l.done = make(chan struct{})

	for _, target := range regexp.MustCompile(`(file|console|syslog|option|purge|compress)\s*\(([^\)]*)\)`).FindAllStringSubmatch(target, -1) {
		switch strings.ToLower(target[1]) {
		case "syslog":
			l.syslog = true
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
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
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
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
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
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
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
				option[2] = strings.ToLower(option[2])
				switch strings.ToLower(option[1]) {
				case "utc":
					l.optionUTC = j.Boolean(option[2])

				case "level":
					if value, exists := severities[option[2]]; exists {
						l.level = value
					}
				}
			}

		case "purge":
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
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
			for _, option := range optionMatcher.FindAllStringSubmatch(target[2], -1) {
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
	}

	go func(l *ULog) {
		ticker, last := time.NewTicker(10*time.Second), time.Now()
		for {
			select {
			case <-ticker.C:

			case <-l.done:
				ticker.Stop()
				return
			}

			go func() {
				l.mu.Lock()
				for path, element := range l.fileOutputs {
					output := element.Value.(*fileOutput)
					if time.Since(output.active) >= time.Minute {
						output.handle.Close()
						delete(l.fileOutputs, path)
						l.lru.Remove(element)
					}
				}
				l.mu.Unlock()
			}()

			if time.Since(last) < 10*time.Minute {
				continue
			}
			last = time.Now()

			go func() {
				l.mu.RLock()

				go func(purge string, age time.Duration, count int) {
					if purge == "" || (age <= 0 && count <= 0) {
						return
					}

					root, err := os.OpenRoot(l.root)
					if err != nil {
						return
					}
					defer root.Close()
					paths, err := filepath.Glob(purge)
					if err != nil {
						return
					}
					entries := []*fileOutput{}
					for _, path := range paths {
						if !filepath.IsAbs(path) {
							if value, err := filepath.Abs(path); err == nil {
								path = value
							}
						}
						if info, err := root.Stat(strings.TrimPrefix(path, l.root+file.Sep)); err == nil && info.Mode().IsRegular() {
							entries = append(entries, &fileOutput{active: info.ModTime(), path: path})
						}
					}
					sort.Slice(entries, func(i, j int) bool {
						return entries[i].active.After(entries[j].active)
					})

					for index, entry := range entries {
						if (age > 0 && time.Since(entry.active) >= age) || (count > 0 && index >= count) {
							for entry.path != l.root {
								root.Remove(entry.path)
								entry.path = filepath.Dir(entry.path)
							}
						}
					}
				}(l.purgePath, l.purgeAge, l.purgeCount)

				go func(compress string, age time.Duration) {
					if compress == "" || age <= 0 {
						return
					}

					root, err := os.OpenRoot(l.root)
					if err != nil {
						return
					}
					defer root.Close()
					paths, err := filepath.Glob(compress)
					if err != nil {
						return
					}

					start := time.Now()
					for _, path := range paths {
						if !filepath.IsAbs(path) {
							if value, err := filepath.Abs(path); err == nil {
								path = value
							}
						}
						path = strings.TrimPrefix(path, l.root+file.Sep)
						if info, err := root.Stat(path); err == nil && info.Mode().IsRegular() /*&& time.Since(info.ModTime()) >= age*/ {
							ok := false
							if source, err := root.Open(path); err == nil {
								if target, err := root.OpenFile(path+".gz", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600); err == nil {
									gzwriter := gzip.NewWriter(target)
									_, err1 := io.Copy(gzwriter, source)
									err2 := gzwriter.Close()
									target.Close()
									if err1 == nil && err2 == nil {
										if err := root.Chtimes(path+".gz", time.Time{}, info.ModTime()); err == nil {
											ok = true
										}
									}
								}
								source.Close()
							}
							if ok {
								root.Remove(path)

							} else {
								root.Remove(path + ".gz")
							}
						}

						if time.Since(start) >= 5*time.Minute {
							break
						}
					}
				}(l.compressPath, l.compressAge)

				l.mu.RUnlock()
			}()
		}
	}(l)

	return l
}

func (l *ULog) Close() {
	l.mu.Lock()
	if l.done != nil {
		close(l.done)
		l.done = nil
	}
	for path, element := range l.fileOutputs {
		element.Value.(*fileOutput).handle.Close()
		delete(l.fileOutputs, path)
	}
	if l.lru != nil {
		l.lru = l.lru.Init()
	}
	if l.syslogHandle != nil {
		l.syslogHandle.Close()
		l.syslogHandle = nil
	}
	time.Sleep(time.Second / 5)
	l.mu.Unlock()
}

func (l *ULog) SetLevel(level string) {
	l.mu.Lock()
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
	l.mu.Unlock()
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
	l.order = slices.Clone(names)
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

func (l *ULog) Log(now time.Time, severity int, in any) {
	l.mu.RLock()
	ssyslog, sexternal, sfile, sconsole := l.syslog, l.external, l.file, l.console
	if l.done == nil || l.level < severity || (!ssyslog && sexternal == nil && !sfile && !sconsole) {
		l.mu.RUnlock()
		return
	}
	sfields, sorder, sutc, spath := maps.Clone(l.fields), slices.Clone(l.order), l.optionUTC, l.filePath
	l.mu.RUnlock()

	structured, content := false, l.arena.Get(1<<10)
	defer func() {
		l.arena.Put(content)
	}()

	templates := map[string]any{
		"datetime":    now.Format(time.DateTime),
		"msdatetime":  now.Format(time.DateTime + ".000"),
		"timestamp":   now.Unix(),
		"mstimestamp": now.UnixNano() / int64(time.Millisecond),
	}
	if structure, ok := in.(map[string]any); ok {
		structure, structured = maps.Clone(structure), true
		for key, value := range sfields {
			if _, exists := structure[key]; !exists {
				structure[key] = value
			}
		}

		for okey, value := range structure {
			key := strings.TrimSpace(okey)
			if strings.HasPrefix(key, "{{") && strings.HasSuffix(key, "}}") {
				delete(structure, okey)
				key = strings.ToLower(strings.TrimSpace(key[2 : len(key)-2]))
				if key == "order" {
					if value, ok := value.(string); ok {
						norder := strings.Fields(value)
						for _, field := range norder {
							if index := slices.Index(sorder, field); index >= 0 {
								sorder = slices.Delete(sorder, index, index+1)
							}
						}
						sorder = append(sorder, norder...)
					}

				} else {
					templates[key] = value
				}
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
			content = append(content,
				bytes.Map(func(r rune) rune {
					if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
						return -1
					}
					return r
				}, []byte(value))...,
			)

		} else {
			buffer := bytes.NewBuffer([]byte{'{'})
			if len(structure) != 0 {
				encoder := json.NewEncoder(buffer)
				encoder.SetEscapeHTML(false)
				for _, key := range sorder {
					if _, exists := structure[key]; exists {
						if value, err := json.Marshal(key); err == nil {
							buffer.Write(value)
							buffer.WriteByte(':')
							encoder.Encode(structure[key])
							buffer.Truncate(buffer.Len() - 1)
							buffer.WriteByte(',')
						}
					}
				}
				for _, key := range j.MapKeys(structure) {
					if !slices.Contains(sorder, key) {
						if value, err := json.Marshal(key); err == nil {
							buffer.Write(value)
							buffer.WriteByte(':')
							encoder.Encode(structure[key])
							buffer.Truncate(buffer.Len() - 1)
							buffer.WriteByte(',')
						}
					}
				}
				buffer.Truncate(buffer.Len() - 1)
			}
			buffer.WriteByte('}')
			content = append(content, buffer.Bytes()...)
		}
	}

	if value, ok := in.(string); ok {
		content = append(content, bytes.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
				return -1
			}
			return r
		}, []byte(value))...)
	}

	if len(content) == 0 {
		return
	}

	if ssyslog {
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
		handle := l.syslogHandle
		l.mu.Unlock()
		if handle != nil {
			switch severity {
			case LOG_ERR:
				handle.Err(string(content))

			case LOG_WARNING:
				handle.Warning(string(content))

			case LOG_INFO:
				handle.Info(string(content))

			case LOG_DEBUG:
				handle.Debug(string(content))
			}
		}
	}

	if sexternal != nil {
		sexternal(severityNames[severity], bytes.Clone(content))
	}

	content = append(content, '\n')
	if sutc {
		now = now.UTC()

	} else {
		now = now.Local()
	}
	if sfile {
		path := ustr.Strftime(spath, now)
		if structured {
			path = templateMatcher.ReplaceAllStringFunc(path, func(key string) string {
				key = strings.ToLower(strings.TrimSpace(key[2 : len(key)-2]))
				if value, ok := templates[key]; ok {
					if value, ok := value.(string); ok {
						return value
					}
				}
				return ""
			})
		}

		if !filepath.IsAbs(path) {
			if value, err := filepath.Abs(path); err == nil {
				path = value
			}
		}
		if ext := filepath.Ext(path); ext == "" || ext != filepath.Base(path) {
			l.mu.Lock()
			if output, exists := l.fileOutputs[path]; !exists {
				if os.MkdirAll(l.root, 0o700) == nil {
					if root, err := os.OpenRoot(l.root); err == nil {
						rpath := strings.TrimPrefix(path, l.root+file.Sep)
						if root.MkdirAll(filepath.Dir(rpath), 0o700) == nil {
							if handle, err := root.OpenFile(rpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0o600); err == nil {
								if len(l.fileOutputs) >= 64 {
									if value := l.lru.Back(); value != nil {
										if value := l.lru.Remove(value); value != nil {
											output := value.(*fileOutput)
											output.handle.Close()
											delete(l.fileOutputs, output.path)
										}
									}
								}
								l.fileOutputs[path] = l.lru.PushFront(&fileOutput{path: path, active: time.Now(), handle: handle})
							}
						}
						root.Close()
					}
				}

			} else {
				l.lru.MoveToFront(output)
			}

			if element, exists := l.fileOutputs[path]; exists {
				output := element.Value.(*fileOutput)
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
				_, _ = output.handle.Write(prefix)
				_, _ = output.handle.Write(content)
				output.active = time.Now()
			}

			l.mu.Unlock()
		}
	}

	if sconsole {
		l.mu.Lock()
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
		l.consoleHandle.Write(prefix)
		l.consoleHandle.Write(content)
		l.mu.Unlock()
	}
}

func (l *ULog) Error(in any) {
	l.Log(time.Now(), LOG_ERR, in)
}

func (l *ULog) Warn(in any) {
	l.Log(time.Now(), LOG_WARNING, in)
}

func (l *ULog) Info(in any) {
	l.Log(time.Now(), LOG_INFO, in)
}

func (l *ULog) Debug(in any) {
	l.Log(time.Now(), LOG_DEBUG, in)
}

func (l *ULog) ErrorTime(now time.Time, in any) {
	l.Log(now, LOG_ERR, in)
}

func (l *ULog) WarnTime(now time.Time, in any) {
	l.Log(now, LOG_WARNING, in)
}

func (l *ULog) InfoTime(now time.Time, in any) {
	l.Log(now, LOG_INFO, in)
}

func (l *ULog) DebugTime(now time.Time, in any) {
	l.Log(now, LOG_DEBUG, in)
}
