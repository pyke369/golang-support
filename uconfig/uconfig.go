package uconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/file"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

type active struct {
	name   string
	top    string
	hash   [32]byte
	config any
	mu     sync.RWMutex
	cache  map[string]any
}

type UConfig struct {
	root      string
	maxsize   int
	inline    bool
	input     string
	separator string
	prefix    string
	arena     *bslab.Arena
	mu        sync.RWMutex
	active    *active
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
	esep = []byte{'\n', ' ', '"', '>', '{', '}', '[', ']', ','}
)

func mode(c byte) int {
	switch c {
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

func grow(in []byte, extra int, arena *bslab.Arena) (out []byte) {
	out = in
	if len(in)+extra > cap(in) {
		out = arena.Get(len(in) + extra)
		out = append(out, in...)
		arena.Put(in)
	}

	return
}

func escape(in []byte, start int, arena *bslab.Arena) (out []byte) {
	out = in
	end := len(in) - 1
	if end < 0 || end < start {
		return
	}

	offsets := make([][2]int, 0, min(256, end-start+1))
	for offset := start; offset <= end; offset++ {
		if out[offset] == '"' || out[offset] == '\\' {
			offsets = append(offsets, [2]int{offset, int(out[offset])})
		}
	}
	if len(offsets) == 0 {
		return
	}

	out = grow(out, len(offsets), arena)
	out = out[:len(in)+len(offsets)]
	for index := len(offsets) - 1; index >= 0; index-- {
		offset := offsets[index][0]
		copy(out[offset+2:], out[offset+1:])
		out[offset], out[offset+1] = '\\', byte(offsets[index][1])
	}

	return
}

func expand(in []byte, start int, arena *bslab.Arena) (out []byte) {
	out = in
	end := len(in) - 1
	if end < 0 || end < start {
		return
	}

	offsets, size, instring := make([][2]int, 0, min(256, end-start+1)), 0, false
	for offset := start; offset <= end; offset++ {
		c := out[offset]

		if c == '"' {
			pairs := 0
			for index := offset - 1; index >= start && out[index] == '\\'; index-- {
				pairs++
			}
			if pairs%2 == 0 {
				instring = !instring
			}
		}

		if !instring {
			switch c {
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
	}
	if len(offsets) == 0 {
		return
	}

	out = grow(out, size, arena)
	out = out[:len(in)+size]
	for index := len(offsets) - 1; index >= 0; index-- {
		offset := offsets[index]
		copy(out[offset[0]+offset[1]:], out[offset[0]:])
		for cindex := 0; cindex < offset[1]; cindex++ {
			out[offset[0]+cindex] = ' '
		}
	}

	return
}

func New(in string, extra ...map[string]any) (config *UConfig, err error) {
	config = &UConfig{maxsize: 4 << 20, input: in, separator: ".", arena: bslab.Default}
	if len(extra) != 0 && extra[0] != nil {
		if value, ok := extra[0]["maxsize"].(int); ok {
			config.maxsize = max(64<<10, min(16<<20, value))
		}
		if value, ok := extra[0]["inline"].(bool); ok {
			config.inline = value
		}
		if root := j.String(extra[0]["root"]); root != "" {
			root, err := filepath.Abs(filepath.Clean(root))
			if err != nil {
				return nil, err
			}
			config.root = root
		}
		if value, ok := extra[0]["arena"].(*bslab.Arena); ok {
			config.arena = value
		}
	}

	return config, ustr.Wrap(config.Load(in), "uconfig")
}

func (uc *UConfig) SetSeparator(separator string) {
	uc.separator = separator
}

func (uc *UConfig) SetPrefix(prefix string) {
	uc.prefix = prefix
}

func (uc *UConfig) GetPrefix() string {
	return uc.prefix
}

func (uc *UConfig) Load(in string) (err error) {
	base, err := os.Getwd()
	if err != nil {
		return ustr.Wrap(err, "uconfig")
	}
	payload, name, top, sroot := uc.arena.Get(max(64<<10, 3+len(base)+3+len(in))), "", "", uc.root
	payload = append(payload, '<', '<', '%')
	payload = append(payload, base...)
	payload = append(payload, '>', '>', ' ')
	if uc.inline {
		payload = append(payload, in...)
		if sroot == "" {
			sroot = base
		}

	} else {
		if !filepath.IsAbs(in) {
			in = filepath.Join(base, in)
		}
		name, top = in, filepath.Dir(in)
		payload = append(payload, '<', '<', '~')
		payload = append(payload, in...)
		payload = append(payload, '>', '>')
		if sroot == "" {
			sroot = top
		}
	}
	root, err := os.OpenRoot(sroot)
	if err != nil {
		return ustr.Wrap(err, "uconfig")
	}
	defer root.Close()

	// remove commented-out sections and expand macros
	length, previous, instring, cstart, cmode, mstart, included := len(payload), byte(0), false, -1, -1, -1, map[string]int{}
	for cindex := 0; cindex < length; cindex++ {
		c := payload[cindex]

		if cstart < 0 && c == '"' {
			pairs := 0
			for index := cindex - 1; index >= 0 && payload[index] == '\\'; index-- {
				pairs++
			}
			if pairs%2 == 0 {
				instring = !instring
			}
		}

		if !instring {
			if mstart == -1 {
				if c == '\r' || c == ';' {
					c = '\n'
					payload[cindex] = c

				} else if c == '\t' {
					c = ' '
					payload[cindex] = c
				}

				if cstart == -1 {
					if c == '*' && previous == '/' {
						cstart, cmode = cindex-1, 1

					} else if c == '#' || (c == '/' && previous == '/') {
						cstart, cmode = cindex-1, 2
						if c == '#' {
							cstart = cindex
						}
					}

				} else if (cmode == 1 && c == '/' && previous == '*') || (cmode == 2 && c == '\n') {
					if cmode == 1 {
						payload[cindex] = ' '
					}
					payload = slices.Delete(payload, cstart, cindex)
					cindex = cstart
					length, cstart, cmode = len(payload), -1, -1
					if length > uc.maxsize {
						uc.arena.Put(payload)
						return errors.New("uconfig: size exceeded")
					}
					continue
				}
			}

			if cstart == -1 {
				if mstart == -1 {
					if c == '<' && previous == '<' {
						mstart = cindex - 1
					}

				} else if c == '>' && previous == '>' {
					macro, arg, btrack := byte(0), "", false
					if cindex-mstart >= 4 {
						macro, arg = payload[mstart+2], strings.TrimSpace(string(payload[mstart+3:cindex-1]))
					}

					if macro == '%' {
						base = arg
						mstart = -1

					} else {
						var insert []byte

						switch macro {
						case '~': // files content
							arg = filepath.Clean(arg)
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							arg = strings.TrimPrefix(arg, sroot+file.Sep)

							paths, sizes, size := []string{}, map[string]int{}, 0
							if values, err := fs.Glob(root.FS(), arg); err == nil {
								for _, value := range values {
									info, err := root.Stat(value)
									if err != nil {
										continue
									}
									fsize := info.Size()
									if fsize < 0 || fsize > int64(uc.maxsize) {
										continue
									}
									sizes[value] = int(fsize)
									size += 4 + len(sroot) + 1 + len(value) + 4 + 3*int(fsize) + 4 + len(base) + 3
									paths = append(paths, value)
								}
							}
							if size != 0 {
								if length+size > uc.maxsize {
									uc.arena.Put(payload)
									return errors.New("uconfig: size exceeded")
								}
								insert = uc.arena.Get(size)
								for _, path := range paths {
									arg := filepath.Join(sroot, path)
									included[arg]++
									if included[arg] > 2 {
										return errors.New("uconfig: cyclic include detected")
									}

									nbase := filepath.Dir(arg)
									insert = append(insert, ' ', '<', '<', '%')
									insert = append(insert, nbase...)
									insert = append(insert, '>', '>', '\n', ' ')
									if handle, err := root.Open(path); err == nil {
										start := len(insert)
										insert = insert[:start+sizes[path]]
										if read, err := io.ReadFull(handle, insert[start:]); err != nil || read != sizes[path] {
											insert = insert[:start]

										} else {
											insert = expand(insert, start, uc.arena)
										}
										handle.Close()
									}
									insert = append(insert, ' ', '<', '<', '%')
									insert = append(insert, base...)
									insert = append(insert, '>', '>', '\n', ' ')
									btrack = true
								}
							}

						case '^': // files lines
							arg = filepath.Clean(arg)
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							arg = strings.TrimPrefix(arg, sroot+file.Sep)

							paths, sizes, size, empty := []string{}, map[string]int{}, 0, true
							if values, err := fs.Glob(root.FS(), arg); err == nil {
								for _, value := range values {
									info, err := root.Stat(value)
									if err != nil {
										continue
									}
									fsize := info.Size()
									if fsize < 0 || fsize > int64(uc.maxsize) {
										continue
									}

									lsize := max(256, int(fsize))
									sizes[value] = lsize
									size += lsize + 5*(lsize/2)
									paths = append(paths, value)
								}
							}
							if length+size > uc.maxsize {
								uc.arena.Put(payload)
								return errors.New("uconfig: size exceeded")
							}
							insert = uc.arena.Get(4 + size + 2)
							insert = append(insert, ' ', ' ', '[', ' ')
							for _, path := range paths {
								handle, err := root.Open(path)
								if err != nil {
									continue
								}
								lines := uc.arena.Get(sizes[path])
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
													insert = escape(insert, offset, uc.arena)
													insert = append(insert, '"', ',', ' ')
													empty = false
												}
											}
											start = index + 1
										}
									}
								}
								uc.arena.Put(lines)
								handle.Close()
							}
							if !empty {
								insert = insert[:len(insert)-2]
							}
							insert = append(insert, ']', ' ')

						case '+', '*': // paths
							arg = filepath.Clean(arg)
							if !filepath.IsAbs(arg) {
								arg = filepath.Join(base, arg)
							}
							arg = strings.TrimPrefix(arg, sroot+file.Sep)

							paths, size := []string{}, 0
							if values, err := fs.Glob(root.FS(), arg); err == nil {
								for _, value := range values {
									size += 1 + 2*len(value) + 1
									paths = append(paths, value)
								}
							}
							if length+size > uc.maxsize {
								uc.arena.Put(payload)
								return errors.New("uconfig: size exceeded")
							}
							insert = uc.arena.Get(4 + size + len(paths)*3 + 2)
							insert = append(insert, ' ', ' ', '[', ' ')
							if len(paths) != 0 {
								for _, path := range paths {
									insert = append(insert, '"')
									path = filepath.Base(path)
									start := len(insert)
									if macro == '*' {
										path = strings.TrimSuffix(path, filepath.Ext(path))
									}
									insert = append(insert, path...)
									insert = escape(insert, start, uc.arena)
									insert = append(insert, '"', ',', ' ')
								}
								insert = insert[:len(insert)-2]
							}
							insert = append(insert, ']', ' ')
						}

						payload = grow(payload, len(insert)-(cindex+1-mstart), uc.arena)
						payload = slices.Replace(payload, mstart, cindex+1, insert...)

						cindex = mstart
						if !btrack {
							cindex += len(insert)
						}
						uc.arena.Put(insert)
						length, mstart = len(payload), -1
						if length > uc.maxsize {
							uc.arena.Put(payload)
							return errors.New("uconfig: size exceeded")
						}
						continue
					}
				}
			}
		}
		previous = c
	}
	if cstart != -1 {
		payload = slices.Delete(payload, cstart, len(payload))
	}

	// remove base macros + build tokens list
	tokens := make([][2]int, 0, 4<<10)
	for pass := 1; pass <= 2; pass++ {
		length, previous, instring, cstart, cmode, mstart = len(payload), byte(0), false, 0, -1, -1
		for cindex := 0; cindex < length; cindex++ {
			c := payload[cindex]
			if c == '"' {
				pairs := 0
				for index := cindex - 1; index >= 0 && payload[index] == '\\'; index-- {
					pairs++
				}
				if pairs%2 == 0 {
					instring = !instring
				}
			}

			switch pass {
			case 1:
				if c == '\n' {
					c = ','
					payload[cindex] = c
				}
				if !instring {
					if c == '=' {
						c = ':'
						payload[cindex] = c
					}
					if mstart == -1 {
						if c == '<' && previous == '<' {
							mstart = cindex - 1
						}

					} else if c == '>' && previous == '>' {
						for index := mstart; index <= cindex; index++ {
							payload[index] = ' '
						}
						mstart = -1
					}
				}

			case 2:
				if cmode == -1 {
					cmode = mode(c)
				}
				if (cmode == 0 && !instring) || cmode != 0 {
					if value := mode(c); cmode != value {
						tokens = append(tokens, [2]int{cmode, cindex - cstart})
						cstart, cmode = cindex, value
					}
					if cindex == length-1 {
						tokens = append(tokens, [2]int{cmode, cindex + 1 - cstart})
					}
				}
			}
			previous = c
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
					payload = grow(payload, 1, uc.arena)
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
					payload = grow(payload, 1, uc.arena)
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
				payload = grow(payload, 1, uc.arena)
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
				payload = grow(payload, 1, uc.arena)
				payload = append(payload, '}')
			}
			break
		}
	}

	// compute hash
	source, hasher := uc.arena.Get(1<<10), sha256.New()
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
	uc.arena.Put(source)
	hash := hasher.Sum(nil)

	// activate if needed
	defer uc.arena.Put(payload)
	uc.mu.Lock()
	defer uc.mu.Unlock()
	if uc.active != nil && bytes.Equal(hash, uc.active.hash[:]) {
		return nil
	}

	var config any

	if err := json.Unmarshal(payload, &config); err != nil {
		if syntax, ok := err.(*json.SyntaxError); ok && syntax.Offset < int64(len(payload)) {
			return errors.New("uconfig: " + syntax.Error() + " at character " + strconv.Itoa(int(syntax.Offset)))
		}
		return errors.New("uconfig: " + err.Error())
	}
	uc.active = &active{name: name, top: top, config: config, cache: map[string]any{}}
	copy(uc.active.hash[:], hash)

	return nil
}

func (uc *UConfig) Reload() (changed bool, err error) {
	var hash [32]byte

	uc.mu.RLock()
	if uc.active != nil {
		copy(hash[:], uc.active.hash[:])
	}
	uc.mu.RUnlock()
	if err = uc.Load(uc.input); err != nil {
		return
	}

	uc.mu.RLock()
	defer uc.mu.RUnlock()

	return !bytes.Equal(hash[:], uc.active.hash[:]), nil
}

func (uc *UConfig) Name() string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	if uc.active != nil {
		return uc.active.name
	}

	return ""
}

func (uc *UConfig) Top() string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	if uc.active != nil {
		return uc.active.top
	}

	return ""
}

func (uc *UConfig) Hash() string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	if uc.active != nil {
		return ustr.Hex(uc.active.hash[:])
	}

	return ""
}

func (uc *UConfig) Dump() string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	if uc.active != nil {
		dump := &bytes.Buffer{}
		encoder := json.NewEncoder(dump)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if encoder.Encode(uc.active.config) == nil {
			return dump.String()
		}
	}

	return "{}"
}

func (uc *UConfig) Base(path string) string {
	if index := strings.LastIndex(path, uc.separator); index != -1 {
		return path[index+1:]
	}

	return path
}

func (uc *UConfig) Path(in ...string) string {
	length, size := len(in), 0
	for _, value := range in {
		size += len(value)
	}
	if size == 0 {
		return ""
	}
	out := make([]byte, 0, size+(len(in)*len(uc.separator)))
	for index, value := range in {
		if value != "" {
			out = append(out, value...)
			if index < length-1 {
				out = append(out, uc.separator...)
			}
		}
	}

	return string(out)
}

func (uc *UConfig) Paths(path string) (paths []string) {
	uc.mu.RLock()
	active := uc.active
	uc.mu.RUnlock()
	if active == nil {
		return
	}

	if uc.prefix != "" {
		if path == "" {
			path = uc.prefix

		} else if prefix := uc.prefix + uc.separator; !strings.HasPrefix(path, prefix) {
			path = prefix + path
		}
	}
	active.mu.RLock()
	if active.cache[path] != nil {
		if value, ok := active.cache[path].([]string); ok {
			active.mu.RUnlock()
			return value
		}
	}
	active.mu.RUnlock()

	active.mu.Lock()
	defer active.mu.Unlock()
	current := active.config
	for _, part := range strings.Split(path, uc.separator) {
		if part == "" {
			continue
		}
		if current == nil {
			return
		}

		switch reflect.TypeOf(current).Kind() {
		case reflect.Slice:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current.([]any)) {
				return
			}
			current = current.([]any)[index]

		case reflect.Map:
			if current = current.(map[string]any)[part]; current == nil {
				return
			}

		default:
			return
		}
	}

	switch reflect.TypeOf(current).Kind() {
	case reflect.Slice:
		for index := 0; index < len(current.([]any)); index++ {
			paths = append(paths, path+uc.separator+strconv.Itoa(index))
		}

	case reflect.Map:
		for key := range current.(map[string]any) {
			paths = append(paths, path+uc.separator+key)
		}
	}
	active.cache[path] = paths

	return
}

func (uc *UConfig) Copy(path string) (out any) {
	uc.mu.RLock()
	active := uc.active
	uc.mu.RUnlock()
	if active == nil {
		return
	}

	if uc.prefix != "" {
		if path == "" {
			path = uc.prefix

		} else if prefix := uc.prefix + uc.separator; !strings.HasPrefix(path, prefix) {
			path = prefix + path
		}
	}

	active.mu.RLock()
	defer active.mu.RUnlock()
	current := active.config
	for _, part := range strings.Split(path, uc.separator) {
		if part == "" {
			continue
		}
		if current == nil {
			return
		}

		switch reflect.TypeOf(current).Kind() {
		case reflect.Slice:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current.([]any)) {
				return
			}
			current = current.([]any)[index]

		case reflect.Map:
			if current = current.(map[string]any)[part]; current == nil {
				return
			}

		default:
			return
		}
	}

	// lazy deep-copy
	if content, err := json.Marshal(current); err == nil {
		json.Unmarshal(content, &out)
	}

	return
}

func (uc *UConfig) value(path string) (out string, exists bool) {
	uc.mu.RLock()
	active := uc.active
	uc.mu.RUnlock()
	if active == nil {
		return
	}

	if uc.prefix != "" {
		if prefix := uc.prefix + uc.separator; !strings.HasPrefix(path, prefix) {
			path = prefix + path
		}
	}
	if path == "" {
		return
	}

	active.mu.Lock()
	defer active.mu.Unlock()
	if active.cache[path] != nil {
		if current, ok := active.cache[path].(bool); ok && !current {
			return
		}
		if current, ok := active.cache[path].(string); ok {
			return current, true
		}
	}

	current := active.config
	for _, part := range strings.Split(path, uc.separator) {
		if current == nil {
			return
		}

		switch reflect.TypeOf(current).Kind() {
		case reflect.Slice:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current.([]any)) {
				return
			}
			current = current.([]any)[index]

		case reflect.Map:
			if current = current.(map[string]any)[part]; current == nil {
				return
			}

		default:
			return
		}
	}

	if reflect.TypeOf(current).Kind() == reflect.String {
		active.cache[path] = current.(string)
		return current.(string), true
	}

	return "", false
}

func (uc *UConfig) Boolean(path string, fallback ...bool) bool {
	if value, exists := uc.value(path); exists {
		return j.Boolean(value)
	}
	if len(fallback) > 0 {
		return fallback[0]
	}

	return false
}

func (uc *UConfig) String(path string, fallback ...string) string {
	if value, exists := uc.value(path); exists {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}

	return ""
}

func (uc *UConfig) StringMatch(path, fallback, match string) string {
	return uc.StringMatchCaptures(path, fallback, match)[0]
}

func (uc *UConfig) StringMatchCaptures(path, fallback, match string) []string {
	value, exists := uc.value(path)
	if !exists {
		return []string{fallback}
	}
	if match != "" {
		if matcher, err := rcache.GetErr(match); err == nil {
			if captures := matcher.FindStringSubmatch(value); captures != nil {
				return captures
			}
		}
		return []string{fallback}
	}

	return []string{value}
}

func (uc *UConfig) StringMap(path string) (out map[string]string) {
	if paths := uc.Paths(path); len(paths) != 0 {
		out = map[string]string{}
		for _, key := range paths {
			if value := uc.String(key); value != "" {
				out[uc.Base(key)] = value
			}
		}
	}

	return
}

func (uc *UConfig) Strings(path string, fallback ...[]string) (out []string) {
	if value := strings.TrimSpace(uc.String(path)); value != "" {
		out = append(out, value)

	} else {
		for _, path := range uc.Paths(path) {
			if value := strings.TrimSpace(uc.String(path)); value != "" {
				out = append(out, value)

			} else {
				if value := strings.Join(uc.Strings(path), " "); value != "" {
					out = append(out, value)
				}
			}
		}
	}
	if len(out) == 0 && len(fallback) > 0 {
		return fallback[0]
	}

	return
}

func (uc *UConfig) Integer(path string, extra ...int64) int64 {
	fallback := int64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}

	return uc.IntegerBounds(path, fallback, math.MinInt64, math.MaxInt64)
}

func (uc *UConfig) IntegerBounds(path string, fallback, lowest, highest int64) int64 {
	value, ok := uc.value(path)
	if !ok {
		return fallback
	}
	nvalue, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fallback
	}

	return max(min(nvalue, highest), lowest)
}

func (uc *UConfig) Float(path string, extra ...float64) float64 {
	fallback := float64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}

	return uc.FloatBounds(path, fallback, -math.MaxFloat64, math.MaxFloat64)
}

func (uc *UConfig) FloatBounds(path string, fallback, lowest, highest float64) float64 {
	value, ok := uc.value(path)
	if !ok {
		return fallback
	}
	nvalue, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fallback
	}

	return max(min(nvalue, highest), lowest)
}

func (uc *UConfig) Size(path string, fallback int64, extra ...bool) int64 {
	return uc.SizeBounds(path, fallback, 0, math.MaxInt64, extra...)
}

func (uc *UConfig) SizeBounds(path string, fallback, lowest, highest int64, extra ...bool) int64 {
	if value, ok := uc.value(path); ok {
		return j.SizeBounds(value, fallback, lowest, highest, extra...)
	}

	return fallback
}

func (uc *UConfig) Duration(path string, extra ...float64) time.Duration {
	fallback := float64(0)
	if len(extra) != 0 {
		fallback = extra[0]
	}
	return uc.DurationBounds(path, fallback, 0, math.MaxFloat64)
}

func (uc *UConfig) DurationBounds(path string, fallback, lowest, highest float64) time.Duration {
	if value, ok := uc.value(path); ok {
		return j.DurationBounds(value, fallback, lowest, highest)
	}

	return time.Duration(fallback * float64(time.Second))
}

func Seconds(in time.Duration) float64 {
	return float64(in) / float64(time.Second)
}
