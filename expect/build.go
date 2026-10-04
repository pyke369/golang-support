package expect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

var (
	commandMatcher = rcache.Get(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)
)

func CheckCommand(reader io.Reader, length int, command string) (err error) {
	decoder, depth := xml.NewDecoder(reader), 1

	token, err := decoder.Token()
	if err != nil {
		return ustr.Wrap(err, "expect")
	}
	if value, ok := token.(xml.StartElement); !ok || value.Name.Local != command {
		return errors.New("expect: invalid root element")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return ustr.Wrap(err, "expect")
			}
			break
		}
		switch token.(type) {
		case xml.StartElement:
			depth++

		case xml.EndElement:
			depth--
			if depth < 0 {
				return errors.New("expect: unbalanced elements")
			}
			if depth == 0 && decoder.InputOffset() < int64(length-1) {
				return errors.New("expect: root element early closing")
			}

		case xml.Directive, xml.ProcInst:
			return errors.New("expect: directives not allowed")
		}
	}

	return nil
}

func BuildCommand(command string, extra ...any) (out string, err error) {
	var b bytes.Buffer

	if !commandMatcher.MatchString(command) {
		return "", errors.New("expect: invalid command")
	}
	b.WriteString("<" + command)
	if len(extra) > 1 {
		if attributes, ok := extra[1].(map[string]string); ok {
			keys := []string{}
			for key := range attributes {
				if !commandMatcher.MatchString(key) {
					return "", errors.New("expect: invalid command attribute")
				}
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				b.WriteString(" " + key + `="`)
				xml.EscapeText(&b, []byte(attributes[key]))
				b.WriteString(`"`)
			}
		}
	}
	b.WriteString(">\n")

	if len(extra) > 0 {
		if value, ok := extra[0].(string); ok {
			if value := strings.TrimSpace(value); value != "" {
				b.WriteString(strings.ReplaceAll(value, "><", ">\n<"))
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("</" + command + ">\n")

	if err := CheckCommand(bytes.NewReader(b.Bytes()), b.Len(), command); err != nil {
		return "", ustr.Wrap(err, "expect")
	}

	return b.String(), nil
}
