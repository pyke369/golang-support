package rpack

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type RPACK struct {
	Default  bool
	Modified int64
	Mime     string
	Content  string
	raw      []byte
}

var guzpool = sync.Pool{
	New: func() interface{} {
		return &gzip.Reader{}
	}}

func Pack(root, output, pkgname, funcname, defdoc, exclude string, main bool) {
	var matcher *regexp.Regexp

	if root = strings.TrimSuffix(root, "/"); root == "" || output == "" {
		return
	}
	if pkgname == "" || main {
		pkgname = "main"
	}
	if funcname == "" {
		funcname = "Resources"
	}
	if exclude != "" {
		matcher, _ = regexp.Compile(exclude)
	}
	funcname = strings.ToUpper(funcname[:1]) + funcname[1:]
	entries := map[string]*RPACK{}
	compressor, _ := gzip.NewWriterLevel(nil, gzip.BestCompression)
	count, size, start := 0, int64(0), time.Now()
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		rpath := strings.TrimPrefix(path, root+"/")
		if matcher != nil && matcher.MatchString(rpath) {
			return nil
		}
		if info.Mode()&os.ModeType == 0 {
			for _, part := range strings.Split(rpath, "/") {
				if len(part) > 0 && part[0] == '.' {
					return nil
				}
			}
			pack := &RPACK{Modified: info.ModTime().Unix(), Mime: "text/plain"}
			if rpath == defdoc {
				pack.Default = true
			}
			if mime := mime.TypeByExtension(filepath.Ext(rpath)); mime != "" {
				pack.Mime = mime
			}
			content, _ := ioutil.ReadFile(path)
			compressed := bytes.Buffer{}
			compressor.Reset(&compressed)
			compressor.Write(content)
			compressor.Close()
			pack.Content = base64.StdEncoding.EncodeToString(compressed.Bytes())
			entries[rpath] = pack
			fmt.Fprintf(os.Stderr, "\r%-120.120s ", rpath)
			count++
			size += info.Size()
		}
		return nil
	})
	fmt.Fprintf(os.Stderr, "\r%-120.120s\rpacked %d file(s) %d byte(s) in %v\n", "", count, size, time.Since(start))
	if handle, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
		random := make([]byte, 64)
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
		rand.Read(random)
		uid := fmt.Sprintf("rpack_%8.8x", md5.Sum(random))
		fmt.Fprintf(handle,
			`package %s

import (
    "net/http"
	"time"
	"github.com/pyke369/golang-support/rpack"
)

var %s map[string]*rpack.RPACK = map[string]*rpack.RPACK {
`,
			pkgname, uid)
		for path, entry := range entries {
			fmt.Fprintf(handle,
				`    "%s": &rpack.RPACK{Default:%t, Modified:%d, Mime:"%s", Content:"%s"},
`, path, entry.Default, entry.Modified, entry.Mime, entry.Content)
		}
		fmt.Fprintf(handle,
			`}

func %sGet(path string) (content []byte, err error) {
	content, _, _, err = rpack.Get(%s, path, true)
	return
}

func %sHandler(ttl time.Duration) http.Handler {
	return rpack.Serve(%s, ttl)
}
`, funcname, uid, funcname, uid)
		if main {
			fmt.Fprintf(handle,
				`
func main() {
    http.Handle("/resources/", http.StripPrefix("/resources/", %sHandler(24 * time.Hour)))
    http.ListenAndServe(":8000", nil)
}
`, funcname)
		}
		handle.Close()
	}
}

func Get(pack map[string]*RPACK, rpath string, uncompress bool) (content []byte, mime string, modified int64, err error) {
	if rpath == "" && pack != nil {
		for name, entry := range pack {
			if entry.Default {
				rpath = name
				break
			}
		}
	}
	if pack == nil || pack[rpath] == nil {
		err = fmt.Errorf("rpack: resource not found")
		return
	}
	if pack[rpath].raw == nil {
		if pack[rpath].raw, err = base64.StdEncoding.DecodeString(pack[rpath].Content); err != nil {
			return
		}
	}
	content, mime, modified = pack[rpath].raw, pack[rpath].Mime, pack[rpath].Modified
	if uncompress {
		decompressor := guzpool.Get().(*gzip.Reader)
		decompressor.Reset(bytes.NewReader(pack[rpath].raw))
		content, err = ioutil.ReadAll(decompressor)
		decompressor.Close()
		guzpool.Put(decompressor)
	}
	return
}

func Serve(pack map[string]*RPACK, ttl time.Duration) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead && request.Method != http.MethodGet {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if sttl := ttl / time.Second; sttl > 0 {
			response.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", sttl))
			response.Header().Set("Expires", time.Now().Add(ttl).UTC().Format(http.TimeFormat))
		}
		prefix, resources, content, mime, modified, uncompress := path.Dir(request.URL.Path), strings.Split(request.URL.Path, "+"), []byte{}, "", int64(0), true
		if strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") && request.Header.Get("Range") == "" {
			response.Header().Set("Content-Encoding", "gzip")
			uncompress = false
		}
		for _, resource := range resources {
			rpath := path.Join(prefix, path.Base(resource))
			if pcontent, pmime, pmodified, err := Get(pack, rpath, uncompress); err == nil {
				content, mime = append(content, pcontent...), pmime
				if pmodified > modified {
					modified = pmodified
				}
			} else {
				response.WriteHeader(http.StatusNotFound)
				return
			}
		}
		response.Header().Set("Content-Type", mime)
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		http.ServeContent(response, request, "", time.Unix(modified, 0), bytes.NewReader(content))
	})
}
