package uconfig

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pyke369/golang-support/rcache"
)

type UConfig struct {
	input     string
	config    any
	hash      string
	cache     map[string]any
	separator string
	cacheLock sync.RWMutex
	sync.RWMutex
}

type replacer struct {
	search  *regexp.Regexp
	replace string
	loop    bool
}

var (
	escaped   string
	unescaper *regexp.Regexp
	expander  *regexp.Regexp
	sizer     *regexp.Regexp
	duration1 *regexp.Regexp
	duration2 *regexp.Regexp
	replacers [15]replacer
)

func init() {
	escaped = "{}[],#/*;:= "                                                                                               // match characters within quotes to escape
	unescaper = regexp.MustCompile(`@\d+@`)                                                                                // match escaped characters (to reverse previous escaping)
	expander = regexp.MustCompile(`{{([<=|@&!\-\+_])\s*([^{}]*?)\s*}}`)                                                    // match external content macros
	sizer = regexp.MustCompile(`^(\d+(?:\.\d*)?)\s*([KMGTP]?)(B?)$`)                                                       // match size value
	duration1 = regexp.MustCompile(`(\d+)(Y|MO|D|H|MN|S|MS|US)?`)                                                          // match duration value form1 (free)
	duration2 = regexp.MustCompile(`^(?:(\d+):)?(\d{2}):(\d{2})(?:\.(\d{1,3}))?$`)                                         // match duration value form2 (timecode)
	replacers[0] = replacer{regexp.MustCompile("(?m)^(.*?)(?:#|//).*?$"), `$1`, false}                                     // remove # and // commented portions
	replacers[1] = replacer{regexp.MustCompile(`/\*[^\*]*\*/`), ``, true}                                                  // remove /* */ commented portions
	replacers[2] = replacer{regexp.MustCompile(`(?m)^\s+`), ``, false}                                                     // trim leading spaces
	replacers[3] = replacer{regexp.MustCompile(`(?m)\s+$`), ``, false}                                                     // trim trailing spaces
	replacers[4] = replacer{regexp.MustCompile(`(?m)^(\S+)\s+([^{}\[\],;:=]+);$`), "$1 = $2;", false}                      // add missing key-value separators
	replacers[5] = replacer{regexp.MustCompile(`(?m);$`), `,`, false}                                                      // replace ; line terminators by ,
	replacers[6] = replacer{regexp.MustCompile(`(\S+?)\s*[:=]`), `$1:`, false}                                             // replace = key-value separators by :
	replacers[7] = replacer{regexp.MustCompile(`([}\]])(\s*)([^,}\]\s])`), `$1,$2$3`, false}                               // add missing objects/arrays , separators
	replacers[8] = replacer{regexp.MustCompile("(?m)(^[^:]+:.+?[^,])$"), `$1,`, false}                                     // add missing values trailing , seperators
	replacers[9] = replacer{regexp.MustCompile(`(?m)(^[^\[{][^:\[{]+)\s+([\[{])`), `$1:$2`, true}                          // add missing key-(object/array-)value separator
	replacers[10] = replacer{regexp.MustCompile(`(?m)^([^":{}\[\]]+)`), `"$1"`, false}                                     // add missing quotes around keys
	replacers[11] = replacer{regexp.MustCompile("([:,\\[\\s]+)([^\",\\[\\]{}\\s\n\r]+?)(\\s*[,\\]}])"), `$1"$2"$3`, false} // add missing quotes around values
	replacers[12] = replacer{regexp.MustCompile("\"[\r\n]"), "\",\n", false}                                               // add still issing objects/arrays , separators
	replacers[13] = replacer{regexp.MustCompile(`"\s*(.+?)\s*"`), `"$1"`, false}                                           // trim leading and trailing spaces in quoted strings
	replacers[14] = replacer{regexp.MustCompile(`,+(\s*[}\]])`), `$1`, false}                                              // remove objets/arrays last element extra ,
}

func escape(input string) string {
	var output []byte

	instring := false
	for index := 0; index < len(input); index++ {
		if input[index:index+1] == `"` && (index == 0 || input[index-1:index] != `\`) {
			instring = !instring
		}
		if instring {
			offset := strings.IndexAny(escaped, input[index:index+1])
			if offset >= 0 {
				output = append(output, []byte(fmt.Sprintf("@%02d@", offset))...)
			} else {
				output = append(output, input[index:index+1]...)
			}
		} else {
			output = append(output, input[index:index+1]...)
		}
	}
	return string(output)
}

func unescape(input string) string {
	return unescaper.ReplaceAllStringFunc(input, func(a string) string {
		offset, _ := strconv.Atoi(a[1:3])
		if offset < len(escaped) {
			return escaped[offset : offset+1]
		}
		return ""
	})
}

func reduce(input any) {
	if input != nil {
		switch reflect.TypeOf(input).Kind() {
		case reflect.Map:
			for key := range input.(map[string]any) {
				var parts []string
				for _, value := range strings.Split(key, " ") {
					if value != "" {
						parts = append(parts, value)
					}
				}
				if len(parts) > 1 {
					if input.(map[string]any)[parts[0]] == nil || reflect.TypeOf(input.(map[string]any)[parts[0]]).Kind() != reflect.Map {
						input.(map[string]any)[parts[0]] = make(map[string]any)
					}
					input.(map[string]any)[parts[0]].(map[string]any)[parts[1]] = input.(map[string]any)[key]
					delete(input.(map[string]any), key)
				}
			}
			for _, value := range input.(map[string]any) {
				reduce(value)
			}
		case reflect.Slice:
			for index := 0; index < len(input.([]any)); index++ {
				reduce(input.([]any)[index])
			}
		}
	}
}

func New(input string, inline ...bool) (*UConfig, error) {
	config := &UConfig{
		input:     input,
		config:    nil,
		separator: ".",
	}
	return config, config.Load(input, inline...)
}

func (c *UConfig) Reload(inline ...bool) error {
	return c.Load(c.input, inline...)
}

func (c *UConfig) SetSeparator(separator string) {
	c.separator = separator
}

func (c *UConfig) Load(input string, inline ...bool) error {
	c.Lock()
	base, _ := os.Getwd()
	content := fmt.Sprintf("/*base:%s*/\n", base)
	if len(inline) > 0 && inline[0] {
		content += input
	} else {
		content += fmt.Sprintf("{{<%s}}", input)
	}

	for {
		indexes := expander.FindStringSubmatchIndex(content)
		if indexes == nil {
			content = escape(content)
			for index := 0; index < len(replacers); index++ {
				mcontent := ""
				for mcontent != content {
					mcontent = content
					content = replacers[index].search.ReplaceAllString(content, replacers[index].replace)
					if !replacers[index].loop {
						break
					}
				}
			}
			content = unescape(strings.Trim(content, " \n,"))
			break
		}

		expanded := ""
		arguments := strings.Split(content[indexes[4]:indexes[5]], " ")
		if start := strings.LastIndex(content[0:indexes[2]], "/*base:"); start >= 0 {
			if end := strings.Index(content[start+7:indexes[2]], "*/"); end > 0 {
				base = content[start+7 : start+7+end]
			}
		}
		switch content[indexes[2]:indexes[3]] {
		case "<":
			if arguments[0][0:1] != "/" {
				arguments[0] = fmt.Sprintf("%s/%s", base, arguments[0])
			}
			nbase := ""
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					if mcontent, err := os.ReadFile(element); err == nil {
						nbase = filepath.Dir(element)
						expanded += string(mcontent)
					}
				}
			}
			if nbase != "" && strings.Contains(expanded, "\n") {
				expanded = fmt.Sprintf("/*base:%s*/\n%s\n/*base:%s*/\n", nbase, expanded, base)
			}
		case "=":
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					if mcontent, err := os.ReadFile(element); err == nil {
						for _, line := range strings.Split(string(mcontent), "\n") {
							line = strings.TrimSpace(line)
							if (len(line) >= 1 && line[0] != '#') || (len(line) >= 2 && line[0] != '/' && line[1] != '/') {
								expanded += fmt.Sprintf("\"%s\"\n", line)
							}
						}
					}
				}
			}
		case "|":
			if arguments[0][0:1] != "/" {
				arguments[0] = fmt.Sprintf("%s/%s", base, arguments[0])
			}
			nbase := ""
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					if element[0:1] != "/" {
						element = fmt.Sprintf("%s/%s", base, element)
					}
					if mcontent, err := exec.Command(element, strings.Join(arguments[1:], " ")).Output(); err == nil {
						nbase = filepath.Dir(element)
						expanded += string(mcontent)
					}
				}
			}
			if nbase != "" && strings.Contains(expanded, "\n") {
				expanded = fmt.Sprintf("/*base:%s*/\n%s\n/*base:%s*/\n", nbase, expanded, base)
			}
		case "@":
			requester := http.Client{
				Timeout: time.Duration(5 * time.Second),
			}
			if response, err := requester.Get(arguments[0]); err == nil {
				if (response.StatusCode / 100) == 2 {
					if mcontent, err := io.ReadAll(response.Body); err == nil {
						expanded += string(mcontent)
					}
				}
			}
		case "&":
			expanded += os.Getenv(arguments[0])
		case "!":
			if matcher := rcache.Get(fmt.Sprintf(`(?i)^--?(no-?)?(?:%s)(?:(=)(.+))?$`, arguments[0])); matcher != nil {
				for index := 1; index < len(os.Args); index++ {
					option := os.Args[index]
					if option == "--" {
						break
					}
					if captures := matcher.FindStringSubmatch(option); captures != nil {
						if captures[2] == "=" {
							expanded = captures[3]
						} else {
							if index == len(os.Args)-1 || strings.HasPrefix(os.Args[index+1], "-") {
								expanded = "true"
								if captures[1] != "" {
									expanded = "false"
								}
							} else {
								expanded = os.Args[index+1]
							}
						}
						break
					}
				}
			}
		case "-":
			if index := strings.Index(os.Args[0], "-"); index >= 0 {
				expanded = strings.ToLower(os.Args[0][index+1:])
			}
		case "+":
			if arguments[0][0:1] != "/" {
				arguments[0] = fmt.Sprintf("%s/%s", base, arguments[0])
			}
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					element = filepath.Base(element)
					expanded += fmt.Sprintf("%s ", strings.TrimSuffix(element, filepath.Ext(element)))
				}
			}
			expanded = strings.TrimSpace(expanded)
		case "_":
			expanded = filepath.Base(input)
		}
		content = fmt.Sprintf("%s%s%s", content[0:indexes[0]], expanded, content[indexes[1]:])
	}

	var config any
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		if err := json.Unmarshal([]byte("{"+content+"}"), &config); err != nil {
			if syntax, ok := err.(*json.SyntaxError); ok && syntax.Offset < int64(len(content)) {
				if start := strings.LastIndex(content[:syntax.Offset], "\n") + 1; start >= 0 {
					line := strings.Count(content[:start], "\n") + 1
					c.Unlock()
					return fmt.Errorf("uconfig: %s at line %d near %s", syntax, line, content[start:syntax.Offset])
				}
			}
			c.Unlock()
			return err
		}
	}

	c.config = config
	c.hash = fmt.Sprintf("%x", sha1.Sum([]byte(content)))
	c.cache = map[string]any{}
	reduce(c.config)
	c.Unlock()
	return nil
}

func (c *UConfig) Loaded() bool {
	c.RLock()
	defer c.RUnlock()
	return !(c.config == nil)
}

func (c *UConfig) Hash() string {
	c.RLock()
	defer c.RUnlock()
	return c.hash
}

func (c *UConfig) String() string {
	if c.config != nil {
		config := &bytes.Buffer{}
		encoder := json.NewEncoder(config)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if encoder.Encode(c.config) == nil {
			return config.String()
		}
	}
	return "{}"
}

func (c *UConfig) Path(input ...string) string {
	total, count, separator := 0, 0, len(c.separator)
	for _, value := range input {
		if length := len(value); length > 0 {
			total += length
			count++
		}
	}
	if total == 0 {
		return ""
	}
	total += (count - 1) * separator
	result, offset := make([]byte, total), 0
	for _, value := range input {
		if length := len(value); length > 0 {
			if offset > 0 {
				copy(result[offset:], c.separator)
				offset += separator
			}
			copy(result[offset:], value)
			offset += length
		}
	}
	return unsafe.String(unsafe.SliceData(result), total)
}

func (c *UConfig) Base(path string) string {
	parts := strings.Split(path, c.separator)
	return parts[len(parts)-1]
}

func (c *UConfig) GetPaths(path string) []string {
	var (
		current any      = c.config
		paths   []string = []string{}
	)

	c.RLock()
	prefix := ""
	if current == nil || path == "" {
		c.RUnlock()
		return paths
	}
	c.cacheLock.RLock()
	if c.cache[path] != nil {
		if paths, ok := c.cache[path].([]string); ok {
			c.cacheLock.RUnlock()
			c.RUnlock()
			return paths
		}
	}
	c.cacheLock.RUnlock()
	if path != "" {
		prefix = c.separator
		for _, part := range strings.Split(path, c.separator) {
			kind := reflect.TypeOf(current).Kind()
			index, err := strconv.Atoi(part)
			if (kind == reflect.Slice && (err != nil || index < 0 || index >= len(current.([]any)))) || (kind != reflect.Slice && kind != reflect.Map) {
				c.cacheLock.Lock()
				c.cache[path] = paths
				c.cacheLock.Unlock()
				c.RUnlock()
				return paths
			}
			if kind == reflect.Slice {
				current = current.([]any)[index]
			} else {
				if current = current.(map[string]any)[strings.TrimSpace(part)]; current == nil {
					c.cacheLock.Lock()
					c.cache[path] = paths
					c.cacheLock.Unlock()
					c.RUnlock()
					return paths
				}
			}
		}
	}
	switch reflect.TypeOf(current).Kind() {
	case reflect.Slice:
		for index := 0; index < len(current.([]any)); index++ {
			paths = append(paths, fmt.Sprintf("%s%s%d", path, prefix, index))
		}
	case reflect.Map:
		for key := range current.(map[string]any) {
			paths = append(paths, fmt.Sprintf("%s%s%s", path, prefix, key))
		}
	}
	c.cacheLock.Lock()
	c.cache[path] = paths
	c.cacheLock.Unlock()
	c.RUnlock()
	return paths
}

func (c *UConfig) value(path string) (string, error) {
	var current any = c.config

	c.RLock()
	if current == nil || path == "" {
		c.RUnlock()
		return "", errors.New(`uconfig: invalid parameter`)
	}
	c.cacheLock.RLock()
	if c.cache[path] != nil {
		if current, ok := c.cache[path].(bool); ok && !current {
			c.cacheLock.RUnlock()
			c.RUnlock()
			return "", errors.New(`uconfig: invalid path`)
		}
		if current, ok := c.cache[path].(string); ok {
			c.cacheLock.RUnlock()
			c.RUnlock()
			return current, nil
		}
	}
	c.cacheLock.RUnlock()
	for _, part := range strings.Split(path, c.separator) {
		kind := reflect.TypeOf(current).Kind()
		index, err := strconv.Atoi(part)
		if (kind == reflect.Slice && (err != nil || index < 0 || index >= len(current.([]any)))) || (kind != reflect.Slice && kind != reflect.Map) {
			c.cacheLock.Lock()
			c.cache[path] = false
			c.cacheLock.Unlock()
			c.RUnlock()
			return "", errors.New(`uconfig: invalid path`)
		}
		if kind == reflect.Slice {
			current = current.([]any)[index]
		} else {
			if current = current.(map[string]any)[strings.TrimSpace(part)]; current == nil {
				c.cacheLock.Lock()
				c.cache[path] = false
				c.cacheLock.Unlock()
				c.RUnlock()
				return "", errors.New(`uconfig: invalid path`)
			}
		}
	}
	if reflect.TypeOf(current).Kind() == reflect.String {
		c.cacheLock.Lock()
		c.cache[path] = current.(string)
		c.cacheLock.Unlock()
		c.RUnlock()
		return current.(string), nil
	}
	c.cacheLock.Lock()
	c.cache[path] = false
	c.cacheLock.Unlock()
	c.RUnlock()
	return "", errors.New(`uconfig: invalid path`)
}

func (c *UConfig) GetBoolean(path string, fallback ...bool) bool {
	if value, err := c.value(path); err == nil {
		if value = strings.ToLower(strings.TrimSpace(value)); value == "1" || value == "on" || value == "yes" || value == "true" {
			return true
		}
		return false
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return false
}

func (c *UConfig) GetStrings(path string) []string {
	list := []string{}
	for _, path := range c.GetPaths(path) {
		list = append(list, c.GetString(path, ""))
	}
	return list
}

func (c *UConfig) GetString(path string, fallback ...string) string {
	if value, err := c.value(path); err == nil {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}
func (c *UConfig) GetStringMatch(path string, fallback, match string) string {
	return c.GetStringMatchCaptures(path, fallback, match)[0]
}
func (c *UConfig) GetStringMatchCaptures(path string, fallback, match string) []string {
	value, err := c.value(path)
	if err != nil {
		return []string{fallback}
	}
	if match != "" {
		if matcher := rcache.Get(match); matcher != nil {
			if matches := matcher.FindStringSubmatch(value); matches != nil {
				return matches
			} else {
				return []string{fallback}
			}
		} else {
			return []string{fallback}
		}
	}
	return []string{value}
}

func (c *UConfig) GetInteger(path string, fallback int64) int64 {
	return c.GetIntegerBounds(path, fallback, math.MinInt64, math.MaxInt64)
}
func (c *UConfig) GetIntegerBounds(path string, fallback, min, max int64) int64 {
	value, err := c.value(path)
	if err != nil {
		return fallback
	}
	nvalue, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fallback
	}
	if nvalue < min {
		nvalue = min
	}
	if nvalue > max {
		nvalue = max
	}
	return nvalue
}

func (c *UConfig) GetFloat(path string, fallback float64) float64 {
	return c.GetFloatBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}
func (c *UConfig) GetFloatBounds(path string, fallback, min, max float64) float64 {
	value, err := c.value(path)
	if err != nil {
		return fallback
	}
	nvalue, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fallback
	}
	return math.Max(math.Min(nvalue, max), min)
}

func (c *UConfig) GetSize(path string, fallback int64) int64 {
	return c.GetSizeBounds(path, fallback, math.MinInt64, math.MaxInt64)
}
func (c *UConfig) GetSizeBounds(path string, fallback, min, max int64) int64 {
	value, err := c.value(path)
	if err != nil {
		return fallback
	}
	nvalue := int64(0)
	if matches := sizer.FindStringSubmatch(strings.TrimSpace(strings.ToUpper(value))); matches != nil {
		fvalue, err := strconv.ParseFloat(matches[1], 64)
		if err != nil {
			return fallback
		}
		scale := float64(1000)
		if matches[3] == "B" {
			scale = float64(1024)
		}
		nvalue = int64(fvalue * math.Pow(scale, float64(strings.Index("_KMGTP", matches[2]))))
	} else {
		return fallback
	}
	if nvalue < min {
		nvalue = min
	}
	if nvalue > max {
		nvalue = max
	}
	return nvalue
}

func (c *UConfig) GetDuration(path string, fallback float64) float64 {
	return c.GetDurationBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}
func (c *UConfig) GetDurationBounds(path string, fallback, min, max float64) float64 {
	value, err := c.value(path)
	if err != nil {
		return fallback
	}
	nvalue := float64(0.0)
	if matches := duration1.FindAllStringSubmatch(strings.TrimSpace(strings.ToUpper(value)), -1); matches != nil {
		for index := 0; index < len(matches); index++ {
			if uvalue, err := strconv.ParseFloat(matches[index][1], 64); err == nil {
				switch matches[index][2] {
				case "Y":
					nvalue += uvalue * 86400 * 365.256
				case "MO":
					nvalue += uvalue * 86400 * 365.256 / 12
				case "D":
					nvalue += uvalue * 86400
				case "H":
					nvalue += uvalue * 3600
				case "MN":
					nvalue += uvalue * 60
				case "S":
					nvalue += uvalue
				case "":
					nvalue += uvalue
				case "MS":
					nvalue += uvalue / 1000
				case "US":
					nvalue += uvalue / 1000000
				}
			}
		}
	}
	if matches := duration2.FindStringSubmatch(strings.TrimSpace(value)); matches != nil {
		hours, _ := strconv.ParseFloat(matches[1], 64)
		minutes, _ := strconv.ParseFloat(matches[2], 64)
		seconds, _ := strconv.ParseFloat(matches[3], 64)
		milliseconds, _ := strconv.ParseFloat(matches[4], 64)
		nvalue = (hours * 3600) + (math.Min(minutes, 59) * 60) + math.Min(seconds, 59) + (milliseconds / 1000)
	}
	return math.Max(math.Min(nvalue, max), min)
}

func Duration(input float64) time.Duration {
	return time.Duration(input * float64(time.Second))
}

func Args() (args []string) {
	for index := 1; index < len(os.Args); index++ {
		option := os.Args[index]
		if args == nil {
			if option[0] == '-' {
				if option != "-" && option != "--" && !strings.Contains(option, "=") && index < len(os.Args)-1 && os.Args[index+1][0] != '-' {
					index++
				}
			} else {
				args = []string{}
			}
		}
		if args != nil {
			args = append(args, option)
		} else if option == "--" {
			args = []string{}
		}
	}
	return
}
