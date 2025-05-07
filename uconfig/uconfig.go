package uconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"hash/crc32"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pyke369/golang-support/bslab"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
)

type UConfig struct {
	size      int
	input     string
	separator string
	hash      uint32
	prefix    string
	top       string
	config    any
	mu        sync.RWMutex
	cache     map[string]any
}

const (
	value  = 0
	space  = 1
	ostart = 2
	oend   = 3
	astart = 4
	aend   = 5
	kvsep  = 6
	vsep   = 7
)

var (
	psep    = string(filepath.Separator)
	esep    = []byte{'\n', ' ', '"', '>', '{', '}', '[', ']', ','}
	options = map[string]string{}
)

func init() {
done:
	for aindex, arg := range os.Args {
		if aindex == 0 || arg == "-" || arg[0] != '-' {
			continue
		}
		if arg == "--" {
			break
		}
		parts, index, negate := strings.Split(arg, "-"), 1, false
		for index < len(parts) {
			if parts[index] == "" {
				index++
				if index > 2 {
					break done
				}
				continue
			}
			if strings.EqualFold(parts[index], "no") {
				index++
				negate = true
				continue
			}
			sparts := strings.Split(parts[index], "=")
			name := strings.ToLower(sparts[0])
			if len(sparts) == 1 {
				if !negate && aindex < len(os.Args)-1 && os.Args[aindex+1][0] != '-' {
					options[name] = os.Args[aindex+1]
				} else {
					if negate {
						options[name] = "false"
					} else {
						options[name] = "true"
					}
				}
			} else {
				options[name] = sparts[1]
			}
			break
		}
	}
}

func mode(char byte) int {
	switch char {
	case ' ':
		return space

	case '{':
		return ostart

	case '}':
		return oend

	case '[':
		return astart

	case ']':
		return aend

	case ':':
		return kvsep

	case ',':
		return vsep

	default:
		return value
	}
}

func grow(in []byte, extra int) (out []byte) {
	out = in
	if len(in)+extra > cap(in) {
		out = bslab.Get(len(in) + extra)
		out = append(out, in...)
		bslab.Put(in)
	}
	return
}

func escape(in []byte, extra ...int) (out []byte) {
	out = in
	length := len(out)
	if length == 0 {
		return
	}
	start, end := 0, length
	if len(extra) > 0 {
		start = min(length, max(0, extra[0]))
		if len(extra) > 1 {
			end = min(length, max(0, extra[1]))
		}
	}
	end--
	if end < start {
		return
	}

	offsets := make([]int, 0, min(256, end-start+1))
	for offset := start; offset <= end; offset++ {
		if out[offset] == '"' {
			offsets = append(offsets, offset)
		}
	}
	if len(offsets) == 0 {
		return
	}

	target := length + len(offsets)
	if target > cap(out) {
		out = slices.Grow(out, target)
	}
	out = out[:target]
	for index := len(offsets) - 1; index >= 0; index-- {
		offset := offsets[index]
		copy(out[offset+2:], out[offset+1:])
		out[offset], out[offset+1] = '\\', '"'
	}

	return
}

func expand(in []byte, extra ...int) (out []byte) {
	out = in
	length := len(out)
	if length == 0 {
		return
	}
	start, end := 0, length
	if len(extra) > 0 {
		start = min(length, max(0, extra[0]))
		if len(extra) > 1 {
			end = min(length, max(0, extra[1]))
		}
	}
	end--
	if end < start {
		return
	}

	offsets, size, instring, previous := make([][2]int, 0, min(256, end-start+1)), 0, false, byte(0)
	for offset := start; offset <= end; offset++ {
		char := out[offset]
		if char == '"' && previous != '\\' {
			instring = !instring
		}

		if !instring {
			switch char {
			case '{', '[':
				if offset > start+1 {
					switch out[offset-1] {
					case ' ':
						switch out[offset-2] {
						case ' ':

						case ':', '=':
							out[offset-1] = out[offset-2]
							out[offset-2] = ' '

						default:
							offsets = append(offsets, [2]int{offset - 1, 1})
							size++
						}

					case ':', '=':
						switch out[offset-2] {
						case ' ', '"':

						default:
							offsets = append(offsets, [2]int{offset - 1, 1})
							size++
						}

					default:
						offsets = append(offsets, [2]int{offset, 2})
						size += 2
					}
				}

			case '\n':
				if offset > start && bytes.IndexByte(esep, out[offset-1]) == -1 {
					offsets = append(offsets, [2]int{offset, 1})
					size++
				}
				if offset < end && bytes.IndexByte(esep, out[offset+1]) == -1 {
					offsets = append(offsets, [2]int{offset + 1, 1})
					size++
				}
			}
		}

		previous = char
	}
	if len(offsets) == 0 {
		return
	}

	target := length + size
	if target > cap(out) {
		out = slices.Grow(out, target)
	}
	out = out[:target]
	for index := len(offsets) - 1; index >= 0; index-- {
		offset := offsets[index]
		copy(out[offset[0]+offset[1]:], out[offset[0]:])
		for cindex := 0; cindex < offset[1]; cindex++ {
			out[offset[0]+cindex] = ' '
		}
	}

	return
}

func New(in string, inline ...bool) (config *UConfig, err error) {
	config = &UConfig{size: 64 << 10, input: in, separator: "."}
	err = config.Load(in, inline...)
	return config, err
}

func (c *UConfig) SetSeparator(separator string) {
	c.separator = separator
}

func (c *UConfig) SetPrefix(prefix string) {
	c.prefix = prefix
}

func (c *UConfig) Load(in string, inline ...bool) error {
	base, _ := os.Getwd()
	payload, top := bslab.Get(max(c.size, 3+len(base)+3+len(in))), ""
	payload = append(payload, '<', '<', '%')
	payload = append(payload, base...)
	payload = append(payload, '>', '>', ' ')
	if len(inline) > 0 && inline[0] {
		payload = append(payload, in...)
	} else {
		if filepath.IsAbs(in) {
			top = filepath.Dir(in)
		} else {
			top = filepath.Dir(filepath.Join(base, in))
		}
		payload = append(payload, '<', '<', '~')
		payload = append(payload, in...)
		payload = append(payload, '>', '>')
	}

	// remove commented-out sections and expand macros
	length, previous, instring, cstart, cmode, mstart := len(payload), byte(0), false, -1, -1, -1
	for cindex := 0; cindex < length; cindex++ {
		char := payload[cindex]

		if cstart < 0 && char == '"' && previous != '\\' {
			instring = !instring
		}

		if !instring {
			if mstart == -1 {
				if char == '\r' || char == ';' {
					char = '\n'
					payload[cindex] = char
				} else if char == '\t' {
					char = ' '
					payload[cindex] = char
				}

				if cstart == -1 {
					if char == '*' && previous == '/' {
						cstart, cmode = cindex-1, 1

					} else if char == '#' || (char == '/' && previous == '/') {
						cstart, cmode = cindex-1, 2
						if char == '#' {
							cstart = cindex
						}
					}

				} else if (cmode == 1 && char == '/' && previous == '*') || (cmode == 2 && char == '\n') {
					if cmode == 1 {
						payload[cindex] = ' '
					}
					payload = slices.Delete(payload, cstart, cindex)
					cindex = cstart
					length, cstart, cmode = len(payload), -1, -1
					continue
				}
			}

			if cstart == -1 {
				if mstart == -1 {
					if char == '<' && previous == '<' {
						mstart = cindex - 1
					}

				} else if char == '>' && previous == '>' {
					macro, arg, btrack := byte(0), "", false
					if cindex-mstart >= 4 {
						macro, arg = payload[mstart+2], strings.TrimSpace(string(payload[mstart+3:cindex-1]))
					}

					if macro == '%' {
						base, mstart = arg, -1

					} else {
						var insert []byte

						switch macro {
						case '~', '/': // files content
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							sizes, size := map[string]int{}, 0
							paths, err := filepath.Glob(arg)
							if err == nil {
								for _, path := range paths {
									if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
										sizes[path] = int(info.Size())
										size += 4 + len(path) + 4 + 3*int(info.Size()) + 4 + len(base) + 3
										if macro == '/' {
											size += len(path) + 7*strings.Count(path, psep)
										}
									}
								}
							}
							if size != 0 {
								insert = bslab.Get(size)
								for _, path := range paths {
									nbase, parts := filepath.Dir(path), []string{}
									insert = append(insert, ' ', '<', '<', '%')
									insert = append(insert, nbase...)
									insert = append(insert, '>', '>', '\n', ' ')
									if macro == '/' {
										index := 0
										for index < min(len(nbase), len(arg)) {
											if nbase[index] != arg[index] {
												break
											}
											index++
										}
										if nbase = nbase[index:]; nbase != "" {
											parts = strings.Split(nbase, psep)
											for _, part := range parts {
												insert = append(insert, part...)
												insert = append(insert, ' ', ':', ' ', '{', ' ')
											}
										}
									}
									if handle, err := os.Open(path); err == nil {
										start := len(insert)
										insert = insert[:start+sizes[path]]
										if read, err := handle.Read(insert[start:]); err != nil || read != sizes[path] {
											insert = insert[:start]
										} else {
											insert = expand(insert, start)
										}
										handle.Close()
									}
									for index := 0; index < len(parts); index++ {
										insert = append(insert, ' ', '}')
									}
									insert = append(insert, ' ', '<', '<', '%')
									insert = append(insert, base...)
									insert = append(insert, '>', '>', '\n', ' ')
									btrack = true
								}
							}

						case '^': // files lines
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							sizes, size, empty := map[string]int{}, 0, true
							paths, err := filepath.Glob(arg)
							if err == nil {
								for _, path := range paths {
									if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
										lsize := max(256, int(info.Size()))
										sizes[path] = lsize
										size += lsize + 5*(lsize/2)
									}
								}
							}
							insert = bslab.Get(4 + size + 2)
							insert = append(insert, ' ', ' ', '[', ' ')
							for _, path := range paths {
								handle, err := os.Open(path)
								if err != nil {
									continue
								}
								lines := bslab.Get(sizes[path])
								lines = lines[:sizes[path]]
								if read, err := handle.Read(lines); err == nil {
									lines = lines[:read]
									start := 0
									for index, char := range lines {
										if char == '\n' {
											for _, char := range lines[start:index] {
												if char == ' ' || char == '\t' || char == '\r' {
													start++
													continue
												}
												break
											}
											if start != index {
												end := index - 1
												for end > start {
													char = lines[end]
													if char == '\r' || char == ' ' || char == '\t' {
														end--
														continue
													}
													break
												}
												if start <= end && lines[start] != '#' {
													insert = append(insert, '"')
													offset := len(insert)
													for index := start; index < end+1; index++ {
														if lines[index] == '\t' {
															lines[index] = ' '
														}
													}
													insert = append(insert, lines[start:end+1]...)
													insert = escape(insert, offset)
													insert = append(insert, '"', ',', ' ')
													empty = false
												}
											}
											start = index + 1
										}
									}
								}
								bslab.Put(lines)
								handle.Close()
							}
							if !empty {
								insert = insert[:len(insert)-2]
							}
							insert = append(insert, ']', ' ')

						case '|': // command output
							args := strings.Split(arg, " ")
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							if value, err := exec.CommandContext(ctx, args[0], strings.Join(args[1:], " ")).Output(); err == nil {
								if len(value) > 0 {
									insert = bslab.Get(3 * len(value))
									insert = append(insert, value...)
									insert = expand(insert)
								}
								btrack = true
							}
							cancel()

						case '@': // url content
							client := http.Client{Timeout: 5 * time.Second}
							if response, err := client.Get(arg); err == nil {
								if response.StatusCode/100 == 2 {
									if size := min(256<<10, int(response.ContentLength)); size > 0 {
										insert = bslab.Get(3 * size)
										offset := 0
										for {
											read, err := response.Body.Read(insert[offset:size])
											offset += read
											if err != nil || read == 0 || offset >= size {
												break
											}
										}
										insert = insert[:offset]
										insert = expand(insert)
										btrack = true
									}
								}
								response.Body.Close()
							}

						case '&': // environment value
							value := strings.TrimSpace(os.Getenv(arg))
							insert = bslab.Get(3 + 2*len(value) + 2)
							insert = append(insert, ' ', ' ', '"')
							insert = append(insert, value...)
							insert = escape(insert, 3)
							insert = append(insert, '"', ' ')

						case '!': // argument value
							value := options[strings.ToLower(arg)]
							insert = bslab.Get(3 + 2*len(value) + 2)
							insert = append(insert, ' ', ' ', '"')
							insert = append(insert, value...)
							insert = escape(insert, 3)
							insert = append(insert, '"', ' ')

						case '-': // program subname
							value := ""
							if index := strings.Index(os.Args[0], "-"); index >= 0 {
								value = os.Args[0][index+1:]
							}
							insert = bslab.Get(3 + 2*len(value) + 2)
							insert = append(insert, ' ', ' ', '"')
							insert = append(insert, value...)
							insert = escape(insert, 3)
							insert = append(insert, '"', ' ')

						case '+', '*': // paths
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							size := 0
							paths, err := filepath.Glob(arg)
							if err == nil {
								for _, path := range paths {
									size += 1 + 2*len(path) + 1
								}
							}
							insert = bslab.Get(4 + size + len(paths)*3 + 2)
							insert = append(insert, ' ', ' ', '[', ' ')
							if len(paths) != 0 {
								for _, path := range paths {
									insert = append(insert, '"')
									path = filepath.Base(path)
									start := len(insert)
									if macro == '*' {
										if index := strings.LastIndex(path, "."); index != -1 {
											path = path[:index]
										}
									}
									insert = append(insert, path...)
									insert = escape(insert, start)
									insert = append(insert, '"', ',', ' ')
								}
								insert = insert[:len(insert)-2]
							}
							insert = append(insert, ']', ' ')

						case '_': // configuration basename
							value := ""
							if len(inline) == 0 || !inline[0] {
								value = filepath.Base(in)
							}
							insert = bslab.Get(3 + 2*len(value) + 2)
							insert = append(insert, ' ', ' ', '"')
							insert = append(insert, value...)
							insert = escape(insert, 3)
							insert = append(insert, '"', ' ')
						}

						payload = grow(payload, len(insert)-(cindex+1-mstart))
						payload = slices.Replace(payload, mstart, cindex+1, insert...)

						cindex = mstart
						if !btrack {
							cindex += len(insert)
						}
						bslab.Put(insert)
						length, mstart = len(payload), -1
						continue
					}
				}
			}
		}
		previous = char
	}
	if cstart != -1 {
		payload = slices.Delete(payload, cstart, len(payload))
	}

	// remove base macros + build tokens list
	tokens := make([][2]int, 0, 4<<10)
	for pass := 1; pass <= 2; pass++ {
		length, previous, instring, cstart, cmode, mstart = len(payload), byte(0), false, 0, -1, -1
		for cindex := 0; cindex < length; cindex++ {
			char := payload[cindex]
			if char == '"' && previous != '\\' {
				instring = !instring
			}

			switch pass {
			case 1:
				if char == '\n' {
					char = ','
					payload[cindex] = char
				}
				if !instring {
					if char == '=' {
						char = ':'
						payload[cindex] = char
					}
					if mstart == -1 {
						if char == '<' && previous == '<' {
							mstart = cindex - 1
						}
					} else if char == '>' && previous == '>' {
						for index := mstart; index <= cindex; index++ {
							payload[index] = ' '
						}
						mstart = -1
					}
				}

			case 2:
				if cmode == -1 {
					cmode = mode(char)
				}
				if (cmode == 0 && !instring) || cmode != 0 {
					if value := mode(char); cmode != value {
						tokens = append(tokens, [2]int{cmode, cindex - cstart})
						cstart, cmode = cindex, value
					}
					if cindex == length-1 {
						tokens = append(tokens, [2]int{cmode, cindex + 1 - cstart})
					}
				}
			}
			previous = char
		}
	}

	// remove redundant values separators + add missing quotes
	offset := 0
	for index, token := range tokens {
		length := token[1]
		if token[0] == vsep && length > 1 {
			for cindex := offset + 1; cindex < offset+length; cindex++ {
				payload[cindex] = ' '
			}
		}
		if token[0] == value {
			if payload[offset] != '"' {
				if index > 0 && offset > 0 && payload[offset-1] == ' ' {
					offset--
					payload[offset] = '"'
					tokens[index-1][1]--
				} else {
					payload = grow(payload, 1)
					payload = slices.Insert(payload, offset, '"')
				}
				tokens[index][1]++
				length++
			}
			if payload[offset+length-1] != '"' {
				if index < len(tokens)-1 && offset+length < len(payload)-1 && payload[offset+length] == ' ' {
					payload[offset+length] = '"'
					tokens[index+1][1]--
				} else {
					payload = grow(payload, 1)
					payload = slices.Insert(payload, offset+length, '"')
				}
				tokens[index][1]++
				length++
			}
		}
		offset += length
	}

	// remove extra values separators (reverse pass)
	previous, offset = byte(0xff), len(payload)
	for index := len(tokens) - 1; index >= 0; index-- {
		token := tokens[index]
		cmode := token[0]
		offset -= token[1]
		if cmode == vsep && previous != value && previous != astart {
			for cindex := offset; cindex < offset+token[1]; cindex++ {
				payload[cindex] = ' '
			}
			tokens[index][0], cmode = space, space
		}
		if cmode != space {
			previous = byte(cmode)
		}
	}

	// remove extra values separators (forward pass) + add missing key/value separators
	previous, offset = byte(0xff), 0
	for index, token := range tokens {
		cmode, length := token[0], token[1]
		if cmode == vsep && (previous == 0xff || previous == ostart || previous == astart) {
			for cindex := offset; cindex < offset+token[1]; cindex++ {
				payload[cindex] = ' '
			}
			tokens[index][0], cmode = space, space
		}
		if (cmode == ostart && previous != kvsep) || (cmode == astart && previous != astart && previous != vsep && previous != kvsep) || (cmode == value && previous == value) {
			if index > 0 && offset > 0 && payload[offset-1] == ' ' {
				offset--
				payload[offset] = ':'
				tokens[index-1][1]--
			} else {
				payload = grow(payload, 1)
				payload = slices.Insert(payload, offset, ':')
			}
			tokens[index][1]++
			length++
		}
		if cmode != space {
			previous = byte(cmode)
		}
		offset += length
	}

	// normalize to JSON object
	for _, char := range payload {
		if char != ' ' {
			if char != '{' {
				payload[0] = '{'
				payload = grow(payload, 1)
				payload = append(payload, '}')
			}
			break
		}
	}
	if value := len(payload); value > c.size {
		c.size = value
	}

	// compute hash
	defer bslab.Put(payload)
	source, hasher := bslab.Get(1<<10), crc32.NewIEEE()
	for _, char := range payload {
		if char != ' ' {
			if len(source) < cap(source) {
				source = append(source, char)
			}
			if len(source) == cap(source) {
				hasher.Write(source)
				source = source[:0]
			}
		}
	}
	if len(source) != 0 {
		hasher.Write(source)
	}
	bslab.Put(source)
	if hasher.Sum32() == c.hash {
		return nil
	}

	var config any

	// decode JSON object as resulting configuration
	if err := json.Unmarshal(payload, &config); err != nil {
		if syntax, ok := err.(*json.SyntaxError); ok && syntax.Offset < int64(len(payload)) {
			start, end := max(0, int(syntax.Offset)-30), min(len(payload), int(syntax.Offset)+30)
			return errors.New("uconfig: " + syntax.Error() + " near '" + string(payload[start:end]) + "'")
		}
		return errors.New("uconfig: " + err.Error())
	}
	c.config, c.top, c.hash, c.cache = config, top, hasher.Sum32(), map[string]any{}

	return nil
}

func (c *UConfig) Reload(inline ...bool) error {
	return c.Load(c.input, inline...)
}

func (c *UConfig) Loaded() bool {
	return c.config != nil
}
func (c *UConfig) Top() string {
	return c.top
}
func (c *UConfig) Hash() uint32 {
	return c.hash
}
func (c *UConfig) Dump() string {
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

func (c *UConfig) Path(in ...string) string {
	length, size := len(in), 0
	for _, value := range in {
		size += len(value)
	}
	if size == 0 {
		return ""
	}
	out := make([]byte, 0, size+(len(in)*len(c.separator)))
	for index, value := range in {
		if value != "" {
			out = append(out, value...)
			if index < length-1 {
				out = append(out, c.separator...)
			}
		}
	}
	return unsafe.String(unsafe.SliceData(out), len(out))
}

func (c *UConfig) Base(path string) string {
	if index := strings.LastIndex(path, c.separator); index != -1 {
		return path[index+1:]
	}
	return path
}

func (c *UConfig) Paths(path string) (paths []string) {
	current := c.config
	if c.prefix != "" {
		if path == "" {
			path = c.prefix
		} else if prefix := c.prefix + c.separator; !strings.HasPrefix(path, prefix) {
			path = prefix + path
		}
	}
	if current == nil {
		return
	}

	c.mu.RLock()
	if c.cache[path] != nil {
		if value, ok := c.cache[path].([]string); ok {
			c.mu.RUnlock()
			return value
		}
	}
	c.mu.RUnlock()

	for _, part := range strings.Split(path, c.separator) {
		if part == "" {
			continue
		}

		switch reflect.TypeOf(current).Kind() {
		case reflect.Slice:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current.([]any)) {
				c.mu.Lock()
				c.cache[path] = paths
				c.mu.Unlock()
				return
			}
			current = current.([]any)[index]

		case reflect.Map:
			if current = current.(map[string]any)[part]; current == nil {
				c.mu.Lock()
				c.cache[path] = paths
				c.mu.Unlock()
				return
			}

		default:
			c.mu.Lock()
			c.cache[path] = paths
			c.mu.Unlock()
			return
		}
	}

	switch reflect.TypeOf(current).Kind() {
	case reflect.Slice:
		for index := 0; index < len(current.([]any)); index++ {
			paths = append(paths, path+c.separator+strconv.Itoa(index))
		}

	case reflect.Map:
		for key := range current.(map[string]any) {
			paths = append(paths, path+c.separator+key)
		}
	}

	c.mu.Lock()
	c.cache[path] = paths
	c.mu.Unlock()
	return
}

func (c *UConfig) value(path string) (out string, exists bool) {
	current := c.config
	if c.prefix != "" {
		if prefix := c.prefix + c.separator; !strings.HasPrefix(path, prefix) {
			path = prefix + path
		}
	}
	if current == nil || path == "" {
		return
	}

	c.mu.RLock()
	if c.cache[path] != nil {
		if current, ok := c.cache[path].(bool); ok && !current {
			c.mu.RUnlock()
			return
		}
		if current, ok := c.cache[path].(string); ok {
			c.mu.RUnlock()
			return current, true
		}
	}
	c.mu.RUnlock()

	for _, part := range strings.Split(path, c.separator) {
		switch reflect.TypeOf(current).Kind() {
		case reflect.Slice:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current.([]any)) {
				c.mu.Lock()
				c.cache[path] = false
				c.mu.Unlock()
				return
			}
			current = current.([]any)[index]

		case reflect.Map:
			if current = current.(map[string]any)[part]; current == nil {
				c.mu.Lock()
				c.cache[path] = false
				c.mu.Unlock()
				return
			}

		default:
			c.mu.Lock()
			c.cache[path] = false
			c.mu.Unlock()
			return
		}
	}

	if reflect.TypeOf(current).Kind() == reflect.String {
		c.mu.Lock()
		c.cache[path] = current.(string)
		c.mu.Unlock()
		return current.(string), true
	}

	c.mu.Lock()
	c.cache[path] = false
	c.mu.Unlock()
	return "", false
}

func (c *UConfig) Boolean(path string, fallback ...bool) bool {
	if value, exists := c.value(path); exists {
		return j.Boolean(value)
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return false
}

func (c *UConfig) String(path string, fallback ...string) string {
	if value, exists := c.value(path); exists {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}
func (c *UConfig) StringMatch(path, fallback, match string) string {
	return c.StringMatchCaptures(path, fallback, match)[0]
}
func (c *UConfig) StringMatchCaptures(path, fallback, match string) []string {
	value, exists := c.value(path)
	if !exists {
		return []string{fallback}
	}
	if match != "" {
		if captures := rcache.Get(match).FindStringSubmatch(value); captures != nil {
			return captures
		}
		return []string{fallback}
	}
	return []string{value}
}
func (c *UConfig) StringMap(path string) (out map[string]string) {
	if paths := c.Paths(path); len(paths) != 0 {
		out = map[string]string{}
		for _, key := range paths {
			if value := c.String(key); value != "" {
				out[c.Base(key)] = value
			}
		}
	}
	return
}
func (c *UConfig) Strings(path string) (out []string) {
	if value := strings.TrimSpace(c.String(path)); value != "" {
		out = append(out, value)
	} else {
		for _, path := range c.Paths(path) {
			if value := strings.TrimSpace(c.String(path)); value != "" {
				out = append(out, value)
			} else {
				if value := strings.Join(c.Strings(path), " "); value != "" {
					out = append(out, value)
				}
			}
		}
	}
	return
}

func (c *UConfig) Integer(path string, extra ...int64) int64 {
	fallback := int64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}
	return c.IntegerBounds(path, fallback, math.MinInt64, math.MaxInt64)
}
func (c *UConfig) IntegerBounds(path string, fallback, lowest, highest int64) int64 {
	value, ok := c.value(path)
	if !ok {
		return fallback
	}
	nvalue, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fallback
	}
	return max(min(nvalue, highest), lowest)
}

func (c *UConfig) Float(path string, extra ...float64) float64 {
	fallback := float64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}
	return c.FloatBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}
func (c *UConfig) FloatBounds(path string, fallback, lowest, highest float64) float64 {
	value, ok := c.value(path)
	if !ok {
		return fallback
	}
	nvalue, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fallback
	}
	return max(min(nvalue, highest), lowest)
}

func (c *UConfig) Size(path string, fallback int64, extra ...bool) int64 {
	return c.SizeBounds(path, fallback, 0, math.MaxInt64, extra...)
}
func (c *UConfig) SizeBounds(path string, fallback, lowest, highest int64, extra ...bool) int64 {
	if value, ok := c.value(path); ok {
		return j.SizeBounds(value, fallback, lowest, highest, extra...)
	}
	return fallback
}

func (c *UConfig) Duration(path string, extra ...float64) time.Duration {
	fallback := float64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}
	return c.DurationBounds(path, fallback, 0, math.MaxFloat64)
}
func (c *UConfig) DurationBounds(path string, fallback, lowest, highest float64) time.Duration {
	if value, ok := c.value(path); ok {
		return j.DurationBounds(value, fallback, lowest, highest)
	}
	return time.Duration(fallback * float64(time.Second))
}

func Seconds(in time.Duration) float64 {
	return float64(in) / float64(time.Second)
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
