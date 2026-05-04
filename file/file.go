package file

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

	handle, err := os.OpenFile(path, os.O_RDONLY|O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer handle.Close()
	reader := bufio.NewReader(handle)
	for {
		line, err := reader.ReadString('\n')
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
		if err != nil {
			break
		}
	}

	return
}

func Write(path string, lines []string, extra ...string) error {
	flags := os.O_WRONLY | O_NOFOLLOW
	if len(extra) > 0 {
		extra[0] = strings.ToLower(strings.TrimSpace(extra[0]))
		if strings.Contains(extra[0], "creat") {
			if strings.Contains(extra[0], "dir") {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					return ustr.Wrap(err, "file")
				}
			}
			flags |= os.O_CREATE
		}
		if strings.Contains(extra[0], "append") {
			flags |= os.O_APPEND

		} else {
			flags |= os.O_TRUNC
		}
	}
	handle, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	_, err = handle.WriteString(strings.Join(lines, "\n") + "\n")
	if err != nil {
		handle.Close()
		return ustr.Wrap(err, "file")
	}

	return handle.Close()
}

func Touch(path string, extra ...string) {
	if len(extra) > 0 {
		extra[0] = strings.ToLower(strings.TrimSpace(extra[0]))
		if strings.Contains(extra[0], "dir") {
			os.MkdirAll(filepath.Dir(path), 0o700)
		}
	}
	if handle, err := os.OpenFile(path, os.O_CREATE|O_NOFOLLOW, 0o600); err == nil {
		handle.Close()
	}
}

func Exists(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return ""
}

func IsRegular(path string) os.FileInfo {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		return info
	}

	return nil
}

func IsDir(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.Mode().IsDir()
}

func Link(path string) (base string) {
	if value, err := os.Readlink(path); err == nil {
		base = filepath.Base(value)
	}

	return
}

func Sum(path string) (sum string, size int64) {
	handle, err := os.OpenFile(path, os.O_RDONLY|O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, handle); err != nil {
		return
	}

	return ustr.Hex(hasher.Sum(nil)), info.Size()
}

func Copy(source, target string, extra ...bool) (err error) {
	tflags := os.O_RDWR | os.O_EXCL | O_NOFOLLOW
	if len(extra) > 0 {
		if extra[0] {
			tflags |= os.O_CREATE
		}
	}

	shandle, err := os.OpenFile(source, os.O_RDONLY|O_NOFOLLOW, 0)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	defer shandle.Close()
	sinfo, err := shandle.Stat()
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	ssize := sinfo.Size()

	thandle, err := os.OpenFile(target, tflags, 0o600)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	defer thandle.Close()
	tinfo, err := thandle.Stat()
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	tsize := tinfo.Size()
	if tflags&os.O_CREATE == 0 && tinfo.Mode().IsRegular() && ssize > tsize {
		return errors.New("file: source size > target size")
	}

	copied, err := io.CopyN(thandle, shandle, ssize)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	if copied < ssize {
		return errors.New("file: truncated copy")
	}

	return
}
