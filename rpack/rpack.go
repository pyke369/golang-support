package rpack

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pyke369/golang-support/file"
	"github.com/pyke369/golang-support/uhash"
	"github.com/pyke369/golang-support/ustr"
)

var dpool = sync.Pool{
	New: func() any {
		decoder, _ := zstd.NewReader(nil)
		return decoder
	}}

type RPACK struct {
	Modified     int64
	Mime         string
	Content      string
	mu           sync.Mutex
	raw          []byte
	decompressed []byte
}

func Pack(root, out, pkgname, funcname, include, exclude string, minified bool) error {
	var (
		includer *regexp.Regexp
		excluder *regexp.Regexp
	)

	if root = strings.TrimSuffix(root, "/"); root == "" || out == "" {
		return errors.New("rpack: invalid root path")
	}
	matcher := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !matcher.MatchString(pkgname) {
		return errors.New("rpack: invalid package name")
	}
	if funcname == "" {
		funcname = "Resources"
	}
	if !matcher.MatchString(funcname) {
		return errors.New("rpack: invalid function name")
	}

	if include != "" {
		value, err := regexp.Compile(strings.TrimSpace(include))
		if err != nil {
			return errors.New("rpack: invalid include expression")
		}
		includer = value
	}
	if exclude != "" {
		value, err := regexp.Compile(strings.TrimSpace(exclude))
		if err != nil {
			return errors.New("rpack: invalid exclude expression")
		}
		excluder = value
	}
	if value, err := filepath.EvalSymlinks(root); err == nil {
		root = value
		if value, err := filepath.Abs(root); err == nil {
			root = value
		}
	}

	compressor, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return err
	}
	count, size, csize, start := 0, 0, 0, time.Now()
	entries := map[string]*RPACK{}
	filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rpath := strings.Trim(strings.TrimPrefix(path, root), "/")

		if includer != nil && !includer.MatchString(rpath) {
			return nil
		}
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
				compressor.Close()
				pack.Content = base64.StdEncoding.EncodeToString(compressed.Bytes())
				entries[rpath] = pack

				os.Stderr.WriteString("\r" + ustr.String(rpath, -120))
				count++
				size += len(content)
				csize += compressed.Len()
			}
		}

		return nil
	})

	os.Stderr.WriteString("\r" + ustr.String("", -120))
	if count != 0 {
		scount := ""
		if count > 1 {
			scount = "s"
		}
		os.Stderr.WriteString("\r" +
			"rpack " + strconv.Itoa(count) + " file" + scount +
			" | " + ustr.Int(size, 0, 0, 0) + " >> " + ustr.Int(csize, 0, 0, 0) +
			" | " + strconv.FormatFloat(float64(size)/float64(csize), 'f', 2, 64) + "x" +
			" | " + ustr.Duration(time.Since(start)) +
			" | " + out + "\n",
		)
	}
	handle, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_TRUNC|file.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer handle.Close()

	key, err := uhash.RandKey(8)
	if err != nil {
		return err
	}
	uid := "rpack_" + key
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

func ` + funcname + `Handler(ttl time.Duration, extra ...bool) http.Handler {
    minified := ` + map[bool]string{false: "false", true: "true"}[minified] + `
	if len(extra) != 0 {
	    minified = extra[0]
	}

	return rpack.Serve(` + uid + `, ttl, minified)
}
`)

	return nil
}

func get(pack map[string]*RPACK, rpath string, uncompress bool) (content []byte, ctype string, modified int64, err error) {
	if path.Ext(rpath) == "" {
		rpath += ".html"
	}
	if pack == nil {
		return nil, "", 0, errors.New("rpack: resource not found")
	}
	entry := pack[rpath]
	if entry == nil {
		return nil, "", 0, errors.New("rpack: resource not found")
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.raw == nil {
		value, err := base64.StdEncoding.DecodeString(entry.Content)
		if err != nil {
			return nil, "", 0, ustr.Wrap(err, "rpack")
		}
		entry.raw = value
	}

	content, ctype, modified = entry.raw, entry.Mime, entry.Modified
	if uncompress {
		if entry.decompressed == nil {
			decompressor := dpool.Get().(*zstd.Decoder)
			defer dpool.Put(decompressor)
			if err := decompressor.Reset(bytes.NewReader(entry.raw)); err != nil {
				return nil, "", 0, ustr.Wrap(err, "rpack")
			}
			decompressed, err := io.ReadAll(io.LimitReader(decompressor.IOReadCloser(), 4<<20))
			if err != nil {
				return nil, "", 0, ustr.Wrap(err, "rpack")
			}
			entry.decompressed = decompressed
		}
		content = entry.decompressed
	}

	return
}

func Get(pack map[string]*RPACK, rpath string, uncompress bool) (content []byte, ctype string, modified int64, err error) {
	content, ctype, modified, err = get(pack, rpath, uncompress)

	return bytes.Clone(content), ctype, modified, err
}

func Serve(pack map[string]*RPACK, ttl time.Duration, minified bool, extra ...map[string]string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead && r.Method != http.MethodGet {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if sttl := ttl / time.Second; sttl > 0 {
			rw.Header().Set("Vary", "Accept-Encoding")
			rw.Header().Set("Cache-Control", "max-age="+strconv.FormatInt(int64(sttl), 10))
			rw.Header().Set("Expires", time.Now().Add(ttl).UTC().Format(http.TimeFormat))
		}
		if len(extra) != 0 {
			for k, v := range extra[0] {
				rw.Header().Set(k, v)
			}
		}

		if strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path += "index"
		}
		prefix, resources := path.Dir(r.URL.Path), strings.Split(path.Base(r.URL.Path), "+")
		resources = resources[:min(16, len(resources))]
		if len(resources) > 1 {
			for index1 := 0; index1 < len(resources); index1++ {
				if resource := resources[index1]; resource != "" {
					for index2 := index1 + 1; index2 < len(resources); index2++ {
						if resources[index2] == resource {
							resources[index2] = ""
						}
					}
				}
			}
			resources = slices.DeleteFunc(resources, func(s string) bool { return s == "" })
		}
		resources = resources[:min(8, len(resources))]

		content, ctype, modified, uncompress := []byte{}, "", int64(0), true
		if r.Header.Get("Range") == "" {
			for _, encoding := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
				parts := strings.Split(strings.ToLower(strings.TrimSpace(encoding)), ";")
				if parts[0] = strings.TrimSpace(parts[0]); parts[0] == "zstd" {
					if len(parts) == 1 {
						uncompress = false

					} else if parts[1] = strings.TrimSpace(parts[1]); strings.HasPrefix(parts[1], "q=") {
						if weight, err := strconv.ParseFloat(strings.TrimPrefix(parts[1], "q="), 64); err == nil && weight > 0 {
							uncompress = false
						}
					}
				}
			}
		}
		for _, resource := range resources {
			rpath := strings.TrimPrefix(path.Clean(path.Join(prefix, resource)), "/")
			if minified && pack != nil && (strings.HasSuffix(rpath, ".js") || strings.HasSuffix(rpath, ".css")) && !strings.Contains(rpath, ".min.") {
				ext := path.Ext(rpath)
				if npath := strings.TrimSuffix(rpath, ext) + ".min" + ext; pack[npath] != nil {
					rpath = npath
				}
			}

			if pcontent, pmime, pmodified, err := get(pack, rpath, uncompress); err == nil {
				if !uncompress {
					rw.Header().Set("Content-Encoding", "zstd")
				}
				content = append(content, pcontent...)

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

			if len(content) > 8<<20 {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Content-Type", ctype)
		http.ServeContent(rw, r, "", time.Unix(modified, 0), bytes.NewReader(content))
	})
}
