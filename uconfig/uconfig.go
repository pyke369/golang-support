package uconfig

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

type UConfig struct {
	config    interface{}
	hash      string
	cache     map[string]interface{}
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
	requoter  *regexp.Regexp
	expander  *regexp.Regexp
	sizer     *regexp.Regexp
	duration1 *regexp.Regexp
	duration2 *regexp.Regexp
	replacers [16]replacer
)

func init() {
	escaped = "{}[],#/*;:= "                                                                                                          // match characters within quotes to escape
	unescaper = regexp.MustCompile(`@\d+@`)                                                                                           // match escaped characters (to reverse previous escaping)
	expander = regexp.MustCompile(`{{([<|@&!\-\+])\s*([^{}]*?)\s*}}`)                                                                 // match external content macros
	sizer = regexp.MustCompile(`^(\d+(?:\.\d*)?)\s*([KMGTP]?)(B?)$`)                                                                  // match size value
	duration1 = regexp.MustCompile(`(\d+)(Y|MO|D|H|MN|S|MS|US)?`)                                                                     // match duration value form1 (free)
	duration2 = regexp.MustCompile(`^(?:(\d+):)?(\d{2}):(\d{2})(?:\.(\d{1,3}))?$`)                                                    // match duration value form2 (timecode)
	replacers[0] = replacer{regexp.MustCompile("(?m)^(.*?)(?:#|//).*?$"), `$1`, false}                                                // remove # and // commented portions
	replacers[1] = replacer{regexp.MustCompile(`/\*[^\*]*\*/`), ``, true}                                                             // remove /* */ commented portions
	replacers[2] = replacer{regexp.MustCompile(`(?m)^\s+`), ``, false}                                                                // trim leading spaces
	replacers[3] = replacer{regexp.MustCompile(`(?m)\s+$`), ``, false}                                                                // trim trailing spaces
	replacers[4] = replacer{regexp.MustCompile("(?s)(^|[\r\n]+)\\[([^\\]\r\n]+?)\\](.+?)((?:[\r\n]+\\[)|$)"), "$1$2\n{$3\n}$4", true} // convert INI sections into JSON objects
	replacers[5] = replacer{regexp.MustCompile(`(?m)^(\S+)\s+([^{}\[\],;:=]+);$`), "$1 = $2;", false}                                 // add missing key-value separators
	replacers[6] = replacer{regexp.MustCompile(`(?m);$`), `,`, false}                                                                 // replace ; line terminators by ,
	replacers[7] = replacer{regexp.MustCompile(`(\S+?)\s*[:=]`), `$1:`, false}                                                        // replace = key-value separators by :
	replacers[8] = replacer{regexp.MustCompile(`([}\]])(\s*)([^,}\]\s])`), `$1,$2$3`, false}                                          // add missing objects/arrays , separators
	replacers[9] = replacer{regexp.MustCompile("(?m)(^[^:]+:.+?[^,])$"), `$1,`, false}                                                // add missing values trailing , seperators
	replacers[10] = replacer{regexp.MustCompile(`(^|[,{\[]+\s*)([^:{\[]+?)(\s*[{\[])`), `$1$2:$3`, true}                              // add missing key-(object/array-)value separator
	replacers[11] = replacer{regexp.MustCompile(`(?m)^([^":{}\[\]]+)`), `"$1"`, false}                                                // add missing quotes around keys
	replacers[12] = replacer{regexp.MustCompile("([:,\\[\\s]+)([^\",\\[\\]{}\n\r]+?)(\\s*[,\\]}])"), `$1"$2"$3`, false}               // add missing quotes around values
	replacers[13] = replacer{regexp.MustCompile("\"[\r\n]"), "\",\n", false}                                                          // add still issing objects/arrays , separators
	replacers[14] = replacer{regexp.MustCompile(`"\s*(.+?)\s*"`), `"$1"`, false}                                                      // trim leading and trailing spaces in quoted strings
	replacers[15] = replacer{regexp.MustCompile(`,+(\s*[}\]])`), `$1`, false}                                                         // remove objets/arrays last element extra ,
}

func escape(input string) string {
	var output []byte

	instring := false
	for index := 0; index < len(input); index++ {
		if input[index:index+1] == `"` && (index == 0 || input[index-1:index] != `\`) {
			instring = !instring
		}
		if instring == true {
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

func reduce(input interface{}) {
	if input != nil {
		switch reflect.TypeOf(input).Kind() {
		case reflect.Map:
			for key, _ := range input.(map[string]interface{}) {
				var parts []string
				for _, value := range strings.Split(key, " ") {
					if value != "" {
						parts = append(parts, value)
					}
				}
				if len(parts) > 1 {
					if input.(map[string]interface{})[parts[0]] == nil || reflect.TypeOf(input.(map[string]interface{})[parts[0]]).Kind() != reflect.Map {
						input.(map[string]interface{})[parts[0]] = make(map[string]interface{})
					}
					input.(map[string]interface{})[parts[0]].(map[string]interface{})[parts[1]] = input.(map[string]interface{})[key]
					delete(input.(map[string]interface{}), key)
				}
			}
			for _, value := range input.(map[string]interface{}) {
				reduce(value)
			}
		case reflect.Slice:
			for index := 0; index < len(input.([]interface{})); index++ {
				reduce(input.([]interface{})[index])
			}
		}
	}
}

func New(input string, inline ...bool) (*UConfig, error) {
	config := &UConfig{
		config: nil,
	}
	return config, config.Load(input, inline...)
}

func (this *UConfig) Load(input string, inline ...bool) error {
	this.Lock()
	this.cache = map[string]interface{}{}
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
			base = ""
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					if mcontent, err := ioutil.ReadFile(element); err == nil {
						base = filepath.Dir(element)
						expanded += string(mcontent)
					}
				}
			}
			if base != "" && strings.Index(expanded, "\n") >= 0 {
				expanded = fmt.Sprintf("/*base:%s*/\n%s\n", base, expanded)
			}
		case "|":
			if arguments[0][0:1] != "/" {
				arguments[0] = fmt.Sprintf("%s/%s", base, arguments[0])
			}
			base = ""
			if elements, err := filepath.Glob(arguments[0]); err == nil {
				for _, element := range elements {
					if element[0:1] != "/" {
						element = fmt.Sprintf("%s/%s", base, element)
					}
					if mcontent, err := exec.Command(element, strings.Join(arguments[1:], " ")).Output(); err == nil {
						base = filepath.Dir(element)
						expanded += string(mcontent)
					}
				}
			}
			if base != "" && strings.Index(expanded, "\n") >= 0 {
				expanded = fmt.Sprintf("/*base:%s*/\n%s\n", base, expanded)
			}
		case "@":
			requester := http.Client{
				Timeout: time.Duration(5 * time.Second),
			}
			if response, err := requester.Get(arguments[0]); err == nil {
				if (response.StatusCode / 100) == 2 {
					if mcontent, err := ioutil.ReadAll(response.Body); err == nil {
						expanded += string(mcontent)
					}
				}
			}
		case "&":
			expanded += os.Getenv(arguments[0])
		case "!":
			arguments[0] = strings.ToLower(arguments[0])
			for index := 1; index < len(os.Args); index++ {
				option := strings.ToLower(os.Args[index])
				if option == "--"+arguments[0] {
					if index == len(os.Args)-1 || strings.HasPrefix(os.Args[index+1], "--") {
						expanded = "true"
					} else {
						expanded = os.Args[index+1]
					}
					break
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
					element = path.Base(element)
					expanded += fmt.Sprintf("%s ", strings.TrimSuffix(element, filepath.Ext(element)))
				}
			}
			expanded = strings.TrimSpace(expanded)
		}
		content = fmt.Sprintf("%s%s%s", content[0:indexes[0]], expanded, content[indexes[1]:len(content)])
	}

	this.hash = fmt.Sprintf("%x", sha1.Sum([]byte(content)))
	if err := json.Unmarshal([]byte(content), &this.config); err != nil {
		if err := json.Unmarshal([]byte("{"+content+"}"), &this.config); err != nil {
			this.config = nil
			if syntax, ok := err.(*json.SyntaxError); ok && syntax.Offset < int64(len(content)) {
				if start := strings.LastIndex(content[:syntax.Offset], "\n") + 1; start >= 0 {
					line := strings.Count(content[:start], "\n") + 1
					this.Unlock()
					return errors.New(fmt.Sprintf("%s at line %d near %s", syntax, line, content[start:syntax.Offset]))
				}
			}
			this.Unlock()
			return err
		}
	}

	reduce(this.config)
	this.Unlock()
	return nil
}

func (this *UConfig) Loaded() bool {
	this.RLock()
	defer this.RUnlock()
	return !(this.config == nil)
}

func (this *UConfig) Hash() string {
	this.RLock()
	defer this.RUnlock()
	return this.hash
}

func (this *UConfig) String() string {
	if config, err := json.MarshalIndent(this.config, "  ", "  "); this.config != nil && err == nil {
		return string(config)
	}
	return "{}"
}

func (this *UConfig) GetPaths(path string) []string {
	var (
		current interface{} = this.config
		paths   []string    = []string{}
	)

	this.RLock()
	prefix := ""
	if current == nil || path == "" {
		this.RUnlock()
		return paths
	}
	this.cacheLock.RLock()
	if this.cache[path] != nil {
		if paths, ok := this.cache[path].([]string); ok {
			this.cacheLock.RUnlock()
			this.RUnlock()
			return paths
		}
	}
	this.cacheLock.RUnlock()
	if path != "" {
		prefix = "."
		for _, part := range strings.Split(path, ".") {
			kind := reflect.TypeOf(current).Kind()
			index, err := strconv.Atoi(part)
			if (kind == reflect.Slice && (err != nil || index < 0 || index >= len(current.([]interface{})))) || (kind != reflect.Slice && kind != reflect.Map) {
				this.cacheLock.Lock()
				this.cache[path] = paths
				this.cacheLock.Unlock()
				this.RUnlock()
				return paths
			}
			if kind == reflect.Slice {
				current = current.([]interface{})[index]
			} else {
				if current = current.(map[string]interface{})[strings.TrimSpace(part)]; current == nil {
					this.cacheLock.Lock()
					this.cache[path] = paths
					this.cacheLock.Unlock()
					this.RUnlock()
					return paths
				}
			}
		}
	}
	switch reflect.TypeOf(current).Kind() {
	case reflect.Slice:
		for index := 0; index < len(current.([]interface{})); index++ {
			paths = append(paths, fmt.Sprintf("%s%s%d", path, prefix, index))
		}
	case reflect.Map:
		for key, _ := range current.(map[string]interface{}) {
			paths = append(paths, fmt.Sprintf("%s%s%s", path, prefix, key))
		}
	}
	this.cacheLock.Lock()
	this.cache[path] = paths
	this.cacheLock.Unlock()
	this.RUnlock()
	return paths
}

func (this *UConfig) value(path string) (string, error) {
	var current interface{} = this.config

	this.RLock()
	if current == nil || path == "" {
		this.RUnlock()
		return "", fmt.Errorf("invalid parameter")
	}
	this.cacheLock.RLock()
	if this.cache[path] != nil {
		if current, ok := this.cache[path].(bool); ok && !current {
			this.cacheLock.RUnlock()
			this.RUnlock()
			return "", fmt.Errorf("invalid path")
		}
		if current, ok := this.cache[path].(string); ok {
			this.cacheLock.RUnlock()
			this.RUnlock()
			return current, nil
		}
	}
	this.cacheLock.RUnlock()
	for _, part := range strings.Split(path, ".") {
		kind := reflect.TypeOf(current).Kind()
		index, err := strconv.Atoi(part)
		if (kind == reflect.Slice && (err != nil || index < 0 || index >= len(current.([]interface{})))) || (kind != reflect.Slice && kind != reflect.Map) {
			this.cacheLock.Lock()
			this.cache[path] = false
			this.cacheLock.Unlock()
			this.RUnlock()
			return "", fmt.Errorf("invalid path")
		}
		if kind == reflect.Slice {
			current = current.([]interface{})[index]
		} else {
			if current = current.(map[string]interface{})[strings.TrimSpace(part)]; current == nil {
				this.cacheLock.Lock()
				this.cache[path] = false
				this.cacheLock.Unlock()
				this.RUnlock()
				return "", fmt.Errorf("invalid path")
			}
		}
	}
	if reflect.TypeOf(current).Kind() == reflect.String {
		this.cacheLock.Lock()
		this.cache[path] = current.(string)
		this.cacheLock.Unlock()
		this.RUnlock()
		return current.(string), nil
	}
	this.cacheLock.Lock()
	this.cache[path] = false
	this.cacheLock.Unlock()
	this.RUnlock()
	return "", fmt.Errorf("invalid path")
}

func (this *UConfig) GetBoolean(path string, fallback bool) bool {
	value, err := this.value(path)
	if err != nil {
		return fallback
	}
	if value = strings.ToLower(strings.TrimSpace(value)); value == "1" || value == "on" || value == "yes" || value == "true" {
		return true
	}
	return false
}

func (this *UConfig) GetString(path string, fallback string) string {
	return this.GetStringMatch(path, fallback, "")
}
func (this *UConfig) GetStringMatch(path string, fallback, match string) string {
	return this.GetStringMatchCaptures(path, fallback, match)[0]
}
func (this *UConfig) GetStringMatchCaptures(path string, fallback, match string) []string {
	value, err := this.value(path)
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

func (this *UConfig) GetInteger(path string, fallback int64) int64 {
	return this.GetIntegerBounds(path, fallback, math.MinInt64, math.MaxInt64)
}
func (this *UConfig) GetIntegerBounds(path string, fallback, min, max int64) int64 {
	value, err := this.value(path)
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

func (this *UConfig) GetFloat(path string, fallback float64) float64 {
	return this.GetFloatBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}
func (this *UConfig) GetFloatBounds(path string, fallback, min, max float64) float64 {
	value, err := this.value(path)
	if err != nil {
		return fallback
	}
	nvalue, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fallback
	}
	return math.Max(math.Min(nvalue, max), min)
}

func (this *UConfig) GetSize(path string, fallback int64) int64 {
	return this.GetSizeBounds(path, fallback, math.MinInt64, math.MaxInt64)
}
func (this *UConfig) GetSizeBounds(path string, fallback, min, max int64) int64 {
	value, err := this.value(path)
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

func (this *UConfig) GetDuration(path string, fallback float64) float64 {
	return this.GetDurationBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}
func (this *UConfig) GetDurationBounds(path string, fallback, min, max float64) float64 {
	value, err := this.value(path)
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
