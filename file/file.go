package file

import (
	"crypto/md5"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

func Read(path string, extra ...map[string]any) (lines []string) {
	var matcher *regexp.Regexp

	options, capture, separator := 0, false, ""
	if len(extra) > 0 {
		if value, ok := extra[0]["options"].(string); ok {
			options = ustr.Options(value)
		}
		if value, ok := extra[0]["match"].(string); ok {
			matcher = rcache.Get(strings.TrimSpace(value))
			if value, ok := extra[0]["separator"].(string); ok {
				capture, separator = true, value
			}
		}
	}

	if content, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = ustr.Transform(line, options)
			if line == "" && options&ustr.OptionEmpty != 0 {
				continue
			}
			if matcher != nil {
				captures := matcher.FindStringSubmatch(line)
				if captures == nil {
					continue
				}
				if capture && len(captures) > 1 {
					line = strings.Join(captures[1:], separator)
				}
			}
			lines = append(lines, line)
			if len(lines) != 0 && options&ustr.OptionFirst != 0 {
				return
			}
		}
	}

	return
}

func Write(path string, lines []string, extra ...string) {
	options := os.O_WRONLY
	if len(extra) > 0 {
		extra[0] = strings.ToLower(strings.TrimSpace(extra[0]))
		if strings.Contains(extra[0], "creat") {
			os.MkdirAll(filepath.Dir(path), 0o755)
			options |= os.O_CREATE
		}
		if strings.Contains(extra[0], "append") {
			options |= os.O_APPEND
		} else {
			options |= os.O_TRUNC
		}
	}
	if handle, err := os.OpenFile(path, options, 0o644); err == nil {
		handle.WriteString(strings.Join(lines, "\n") + "\n")
		handle.Close()
	}
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func Link(path string) (base string) {
	if value, err := os.Readlink(path); err == nil {
		base = filepath.Base(value)
	}
	return
}

func Sum(path string) (sum string, size int64) {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		hasher := md5.New()
		if handle, err := os.Open(path); err == nil {
			io.Copy(hasher, handle)
			handle.Close()
		}
		size, sum = info.Size(), ustr.Hex(hasher.Sum(nil))
	}
	return
}

func Copy(source, target string, extra ...bool) (err error) {
	tflags := os.O_RDWR
	if len(extra) > 0 {
		if extra[0] {
			tflags |= os.O_CREATE
		}
	}

	shandle, err := os.Open(source)
	if err != nil {
		return err
	}
	defer shandle.Close()
	sinfo, _ := shandle.Stat()
	ssize := sinfo.Size()

	thandle, err := os.OpenFile(target, tflags, 0o644)
	if err != nil {
		return err
	}
	defer thandle.Close()
	tinfo, _ := thandle.Stat()
	tsize := tinfo.Size()
	if tflags&os.O_CREATE == 0 && tinfo.Mode().IsRegular() && ssize > tsize {
		return errors.New("source size " + strconv.FormatInt(ssize, 10) + " > target size " + strconv.FormatInt(tsize, 10))
	}

	copied, err := io.Copy(thandle, shandle)
	if err != nil {
		return err
	}
	if copied < ssize {
		return errors.New("truncated copy " + strconv.FormatInt(copied, 10) + " < " + strconv.FormatInt(ssize, 10))
	}
	return
}
