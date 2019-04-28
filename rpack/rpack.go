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
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type RPACK struct {
	Compressed bool
	Modified   int64
	Mime       string
	Content    string
	raw        []byte
}

var guzpool = sync.Pool{
	New: func() interface{} {
		return &gzip.Reader{}
	}}

func Pack(root, output, pkgname, funcname string, main bool) {
	root = strings.TrimSuffix(root, "/")
	if root == "" || output == "" {
		return
	}
	if pkgname == "" || main {
		pkgname = "main"
	}
	if funcname == "" {
		funcname = "resources"
	}
	funcname = strings.ToUpper(funcname[:1]) + funcname[1:]
	entries := map[string]*RPACK{}
	compressor, _ := gzip.NewWriterLevel(nil, gzip.BestCompression)
	count := 0
	size := int64(0)
	start := time.Now()
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		rpath := strings.TrimPrefix(path, root+"/")
		if info.Mode()&os.ModeType == 0 {
			for _, part := range strings.Split(rpath, "/") {
				if len(part) > 0 && part[0] == '.' {
					return nil
				}
			}
			pack := &RPACK{Modified: info.ModTime().Unix(), Mime: "text/plain"}
			if mime := mime.TypeByExtension(filepath.Ext(rpath)); mime != "" {
				pack.Mime = mime
			}
			content, _ := ioutil.ReadFile(path)
			compressed := bytes.Buffer{}
			compressor.Reset(&compressed)
			compressor.Write(content)
			compressor.Close()
			if compressed.Len() < len(content) {
				pack.Content = base64.StdEncoding.EncodeToString(compressed.Bytes())
				pack.Compressed = true
			} else {
				pack.Content = base64.StdEncoding.EncodeToString(content)
			}
			entries[rpath] = pack
			fmt.Fprintf(os.Stderr, "\r%-120.120s ", rpath)
			count++
			size += info.Size()
		}
		return nil
	})
	fmt.Fprintf(os.Stderr, "\r%-120.120s\rpacked %d file(s) %d byte(s) in %v\n", "", count, size, time.Now().Sub(start))
	if handle, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
		random := make([]byte, 64)
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
		rand.Read(random)
		uid := fmt.Sprintf("rpack%8.8x", md5.Sum(random))
		fmt.Fprintf(handle,
			`package %s

import (
    "net/http"
	"github.com/pyke369/golang-support/rpack"
)

var %s map[string]*rpack.RPACK = map[string]*rpack.RPACK {
`,
			pkgname, uid)
		for path, entry := range entries {
			fmt.Fprintf(handle,
				`    "%s": &rpack.RPACK{Compressed:%t, Modified:%d, Mime:"%s", Content:"%s"},
`, path, entry.Compressed, entry.Modified, entry.Mime, entry.Content)
		}
		fmt.Fprintf(handle,
			`}

func %s() http.Handler {
	return rpack.Serve(%s)
}
`, funcname, uid)
		if main {
			fmt.Fprintf(handle,
				`
func main() {
    http.Handle("/resources/", http.StripPrefix("/resources/", %s()))
    http.ListenAndServe(":8000", nil)
}
`, funcname)
		}
		handle.Close()
	}
}

func Serve(pack map[string]*RPACK) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var err error
		if pack == nil || pack[request.URL.Path] == nil {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if pack[request.URL.Path].raw == nil {
			if pack[request.URL.Path].raw, err = base64.StdEncoding.DecodeString(pack[request.URL.Path].Content); err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
		}
		resource := pack[request.URL.Path]
		response.Header().Set("Content-Type", resource.Mime)
		if strings.Index(request.Header.Get("Accept-Encoding"), "gzip") >= 0 && request.Header.Get("Range") == "" && resource.Compressed {
			response.Header().Set("Content-Encoding", "gzip")
			response.Header().Set("Content-Length", fmt.Sprintf("%d", len(resource.raw)))
			http.ServeContent(response, request, request.URL.Path, time.Unix(resource.Modified, 0), bytes.NewReader(resource.raw))
		} else {
			if resource.Compressed {
				decompressor := guzpool.Get().(*gzip.Reader)
				decompressor.Reset(bytes.NewReader(resource.raw))
				if raw, err := ioutil.ReadAll(decompressor); err == nil {
					http.ServeContent(response, request, request.URL.Path, time.Unix(resource.Modified, 0), bytes.NewReader(raw))
				}
				decompressor.Close()
				guzpool.Put(decompressor)
			} else {
				http.ServeContent(response, request, request.URL.Path, time.Unix(resource.Modified, 0), bytes.NewReader(resource.raw))
			}
		}
	})
}
