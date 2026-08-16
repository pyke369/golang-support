package expect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/pyke369/golang-support/ustr"
)

var matcher = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)

func BuildCommand(command string, extra ...any) (out string, err error) {
	var b bytes.Buffer

	if !matcher.MatchString(command) {
		return "", errors.New("expect: invalid command")
	}
	b.WriteString("<" + command)
	if len(extra) > 1 {
		if attributes, ok := extra[1].(map[string]string); ok {
			keys := []string{}
			for key := range attributes {
				if !matcher.MatchString(key) {
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

	decoder, depth := xml.NewDecoder(bytes.NewReader(b.Bytes())), 1
	token, err := decoder.Token()
	if err != nil {
		return "", ustr.Wrap(err, "expect")
	}
	if value, ok := token.(xml.StartElement); !ok || value.Name.Local != command {
		return "", errors.New("expect: invalid XML root element")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return "", ustr.Wrap(err, "expect")
			}
			break
		}
		switch token.(type) {
		case xml.StartElement:
			depth++

		case xml.EndElement:
			depth--
			if depth <= 0 && decoder.InputOffset() < int64(b.Len()-1) {
				return "", errors.New("expect: XML root element early closing")
			}
		}
	}

	return b.String(), nil
}
