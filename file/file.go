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

const Sep = string(filepath.Separator)

func Touch(path string, extra ...string) error {
	if len(extra) > 0 {
		extra[0] = strings.ToLower(strings.TrimSpace(extra[0]))
		if strings.Contains(extra[0], "dir") {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return ustr.Wrap(err, "file")
			}
		}
	}
	handle, err := os.OpenFile(path, os.O_CREATE|O_NOFOLLOW, 0o600)
	if err != nil {
		return ustr.Wrap(err, "file")
	}

	return ustr.Wrap(handle.Close(), "file")
}

func Read(path string, extra ...map[string]any) (lines []string, err error) {
	var matcher *regexp.Regexp

	flags, maxsize, options, capture, separator := os.O_RDONLY|O_NOFOLLOW, 4<<20, 0, false, ""
	if len(extra) > 0 {
		if value, ok := extra[0]["follow"].(bool); ok && value {
			flags &= ^O_NOFOLLOW
		}
		if value, ok := extra[0]["maxsize"].(int); ok && value > 0 {
			maxsize = min(16<<20, max(0, value))
		}
		if value, ok := extra[0]["options"].(string); ok {
			options = ustr.Options(value)
		}
		if value, ok := extra[0]["match"].(string); ok {
			value, err := rcache.GetErr(strings.TrimSpace(value))
			if err != nil {
				return nil, ustr.Wrap(err, "file")
			}
			matcher = value
			if value, ok := extra[0]["separator"].(string); ok {
				capture, separator = true, value
			}
		}
	}

	handle, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, ustr.Wrap(err, "file")
	}
	defer handle.Close()
	reader, size := bufio.NewReader(io.LimitReader(handle, int64(maxsize))), 0
	for {
		line, err := reader.ReadString('\n')
		line = ustr.Transform(line, options)
		if line == "" && options&ustr.OptionEmpty != 0 {
			if err != nil {
				break
			}
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
		if size+len(line)+48 > maxsize {
			return nil, errors.New("file: size exceeded")
		}
		lines = append(lines, line)
		size += len(line) + 48
		if len(lines) != 0 && options&ustr.OptionFirst != 0 {
			return lines, nil
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

	} else {
		flags |= os.O_TRUNC
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

	return ustr.Wrap(handle.Close(), "file")
}

func Copy(source, target string, extra ...bool) (err error) {
	sflags, tflags := os.O_RDONLY|O_NOFOLLOW, os.O_WRONLY|O_NOFOLLOW|os.O_CREATE
	if len(extra) > 0 && extra[0] {
		sflags &= ^O_NOFOLLOW
	}

	shandle, err := os.OpenFile(source, sflags, 0)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	defer shandle.Close()
	sinfo, err := shandle.Stat()
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	if !sinfo.Mode().IsRegular() {
		return errors.New("file: source not regular")
	}
	ssize := sinfo.Size()

	thandle, err := os.OpenFile(target, tflags, 0o600)
	if err != nil {
		return ustr.Wrap(err, "file")
	}
	tinfo, err := thandle.Stat()
	if err != nil {
		thandle.Close()
		return ustr.Wrap(err, "file")
	}
	if tinfo.Mode().IsRegular() {
		if err := thandle.Truncate(0); err != nil {
			thandle.Close()
			return ustr.Wrap(err, "file")
		}
	}

	copied, err := io.Copy(thandle, shandle)
	if err != nil {
		thandle.Close()
		return ustr.Wrap(err, "file")
	}
	if copied != ssize {
		thandle.Close()
		return errors.New("file: truncated copy")
	}
	if tinfo.Mode().IsRegular() {
		if err := thandle.Truncate(copied); err != nil {
			thandle.Close()
			return ustr.Wrap(err, "file")
		}
		if err := thandle.Sync(); err != nil {
			thandle.Close()
			return ustr.Wrap(err, "file")
		}
	}

	return ustr.Wrap(thandle.Close(), "file")
}

func Exists(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return ""
}

func Regular(path string) os.FileInfo {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		return info
	}

	return nil
}

func Dir(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.Mode().IsDir()
}

func Link(path string) (base string) {
	if value, err := os.Readlink(path); err == nil {
		base = filepath.Base(value)
	}

	return
}

func Sum256(path string, extra ...bool) (sum string, size int64, err error) {
	flags := os.O_RDONLY | O_NOFOLLOW
	if len(extra) > 0 && extra[0] {
		flags &= ^O_NOFOLLOW
	}

	handle, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return "", 0, ustr.Wrap(err, "file")
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, ustr.Wrap(err, "file")
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, handle); err != nil {
		return "", 0, ustr.Wrap(err, "file")
	}

	return ustr.Hex(hasher.Sum(nil)), info.Size(), nil
}
