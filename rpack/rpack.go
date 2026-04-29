package rpack

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uhash"
	"github.com/pyke369/golang-support/ustr"
)

type RPACK struct {
	Modified int64
	Mime     string
	Content  string
	raw      []byte
}

var (
	mu       sync.Mutex
	x2ntable [32]uint32
	guzpool  = sync.Pool{
		New: func() any {
			return &gzip.Reader{}
		}}
)

// 🔔 SHAME! 🔔 (stolen from https://github.com/madler/zlib/blob/master/crc32.c)

func init() {
	p := uint32(1 << 30)
	x2ntable[0] = p
	for n := 1; n < 32; n++ {
		p = multmodp(p, p)
		x2ntable[n] = p
	}
}

func multmodp(a, b uint32) uint32 {
	m, p := uint32(1<<31), uint32(0)
	for {
		if a&m != 0 {
			p ^= b
			if a&(m-1) == 0 {
				break
			}
		}
		m >>= 1
		if b&1 != 0 {
			b = (b >> 1) ^ crc32.IEEE

		} else {
			b >>= 1
		}
	}

	return p
}

func x2nmodp(n, k uint32) uint32 {
	p := uint32(1 << 31)
	for n > 0 {
		if n&1 != 0 {
			p = multmodp(x2ntable[k&31], p)
		}
		n >>= 1
		k++
	}

	return p
}

func combine(crc1, crc2, len2 uint32) uint32 {
	return multmodp(x2nmodp(len2, 3), crc1) ^ crc2
}

// 🔔 /SHAME! 🔔

func Pack(root, out, pkgname, funcname, exclude string, minified bool) {
	var excluder *regexp.Regexp

	if root = strings.TrimSuffix(root, "/"); root == "" || out == "" {
		return
	}
	matcher := rcache.Get(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !matcher.MatchString(pkgname) || !matcher.MatchString(funcname) {
		return
	}

	if funcname == "" {
		funcname = "Resources"
	}
	if exclude != "" {
		excluder = rcache.Get(exclude)
	}
	entries := map[string]*RPACK{}
	compressor, _ := gzip.NewWriterLevel(nil, gzip.BestCompression)
	count, size, start := 0, int64(0), time.Now()
	if value, err := filepath.EvalSymlinks(root); err == nil {
		root = value
		if value, err := filepath.Abs(root); err == nil {
			root = value
		}
	}
	filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rpath := strings.Trim(strings.TrimPrefix(path, root), "/")

		if excluder != nil && excluder.MatchString(rpath) {
			return nil
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			for _, part := range strings.Split(rpath, "/") {
				if part != "" && part[0] == '.' {
					return nil
				}
			}
			pack := &RPACK{Modified: info.ModTime().Unix(), Mime: "text/plain"}
			if value := mime.TypeByExtension(filepath.Ext(rpath)); value != "" {
				pack.Mime = value
			}
			if content, err := os.ReadFile(path); err == nil {
				compressed := bytes.Buffer{}
				compressor.Reset(&compressed)
				compressor.Write(content)
				compressor.Flush()
				compressor.Close()
				pack.Content = base64.StdEncoding.EncodeToString(compressed.Bytes())
				entries[rpath] = pack
				os.Stderr.WriteString("\r" + ustr.String(rpath, -120))
				count++
				size += info.Size()
			}
		}

		return nil
	})

	os.Stderr.WriteString("\r" + ustr.String("", -120))
	os.Stderr.WriteString("\rpacked " + strconv.Itoa(count) + " file(s) " + strconv.FormatInt(size, 10) + " byte(s) in " + ustr.Duration(time.Since(start)) + "\n")
	if handle, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600); err == nil {
		uid := "rpack_" + uhash.RandKey(8)
		handle.WriteString(`package ` + pkgname + `

import (
	"net/http"
	"time"

	"github.com/pyke369/golang-support/rpack"
)

var ` + uid + ` map[string]*rpack.RPACK = map[string]*rpack.RPACK{
`)
		length := 0
		for path := range entries {
			if value := len(path); value > length {
				length = value
			}
		}
		length += 3
		for path, entry := range entries {
			handle.WriteString(`	` + ustr.String(strconv.Quote(path)+`:`, -length) + ` &rpack.RPACK{Modified: ` + strconv.FormatInt(entry.Modified, 10) + `, Mime: ` + strconv.Quote(entry.Mime) + `, Content: "` + entry.Content + "\"},\n")
		}
		handle.WriteString(`}

func ` + funcname + `Get(path string) (content []byte, err error) {
	content, _, _, err = rpack.Get(` + uid + `, path, true)
	return
}

func ` + funcname + `Handler(ttl time.Duration) http.Handler {
	return rpack.Serve(` + uid + `, ttl, ` + map[bool]string{false: "false", true: "true"}[minified] + `)
}
`)
		handle.Close()
	}
}

func Get(pack map[string]*RPACK, rpath string, uncompress bool) (content []byte, ctype string, modified int64, err error) {
	if path.Ext(rpath) == "" {
		rpath += ".html"
	}
	if pack == nil || pack[rpath] == nil {
		return nil, "", 0, errors.New("rpack: resource not found")
	}

	mu.Lock()
	defer mu.Unlock()
	if pack[rpath].raw == nil {
		value, err := base64.StdEncoding.DecodeString(pack[rpath].Content)
		if err != nil {
			return nil, "", 0, ustr.Wrap(err, "rpack")
		}
		pack[rpath].raw = value
	}
	content, ctype, modified = pack[rpath].raw, pack[rpath].Mime, pack[rpath].Modified
	if uncompress {
		decompressor := guzpool.Get().(*gzip.Reader)
		decompressor.Reset(bytes.NewReader(pack[rpath].raw))
		content, err = io.ReadAll(io.LimitReader(decompressor, 64<<20))
		decompressor.Close()
		guzpool.Put(decompressor)
	}

	return
}

func Serve(pack map[string]*RPACK, ttl time.Duration, minified bool) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead && r.Method != http.MethodGet {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if sttl := ttl / time.Second; sttl > 0 {
			rw.Header().Set("Cache-Control", "max-age="+strconv.FormatInt(int64(sttl), 10)+", public")
			rw.Header().Set("Expires", time.Now().Add(ttl).UTC().Format(http.TimeFormat))
		}

		if strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path += "index"
		}
		prefix, resources := path.Dir(r.URL.Path), strings.Split(path.Base(r.URL.Path), "+")
		if len(resources) > 32 {
			resources = resources[:32]
		}

		content, ctype, modified, check, size, uncompress := []byte{}, "", int64(0), uint32(0), uint32(0), true
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && r.Header.Get("Range") == "" {
			rw.Header().Set("Content-Encoding", "gzip")
			uncompress = false
		}
		for index, resource := range resources {
			rpath := strings.TrimPrefix(path.Join(prefix, resource), "/")
			if minified && pack != nil && (strings.HasSuffix(rpath, ".js") || strings.HasSuffix(rpath, ".css")) && !strings.Contains(rpath, ".min.") {
				ext := path.Ext(rpath)
				if npath := strings.TrimSuffix(rpath, ext) + ".min" + ext; pack[npath] != nil {
					rpath = npath
				}
			}

			if pcontent, pmime, pmodified, err := Get(pack, rpath, uncompress); err == nil {
				if len(resources) > 1 && !uncompress {
					if len(pcontent) < 18 {
						rw.WriteHeader(http.StatusInternalServerError)
						return
					}
					ucheck, usize := binary.LittleEndian.Uint32(pcontent[len(pcontent)-8:]), binary.LittleEndian.Uint32(pcontent[len(pcontent)-4:])
					check = combine(check, ucheck, usize)
					if math.MaxUint32-size < usize {
						rw.WriteHeader(http.StatusInternalServerError)
						return
					}
					size += usize
					if index == 0 {
						content = append(content, []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}...)
					}
					content = append(content, pcontent[10:len(pcontent)-8]...)
					if index == len(resources)-1 {
						content = append(content, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
						binary.LittleEndian.PutUint32(content[len(content)-8:], check)
						binary.LittleEndian.PutUint32(content[len(content)-4:], size)

					} else {
						content[len(content)-5] = 0
					}

				} else {
					content = append(content, pcontent...)
				}

				if ctype == "" {
					ctype = pmime

				} else if pmime != ctype {
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}

				if pmodified > modified {
					modified = pmodified
				}

			} else {
				rw.WriteHeader(http.StatusNotFound)
				return
			}
		}

		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("Content-Security-Policy", "default-src 'none'")
		rw.Header().Set("Content-Type", ctype)
		rw.Header().Set("Content-Length", strconv.Itoa(len(content)))
		http.ServeContent(rw, r, "", time.Unix(modified, 0), bytes.NewReader(content))
	})
}
