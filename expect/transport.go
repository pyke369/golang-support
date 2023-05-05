package expect

import (
	"time"
)

const (
	TEXT = "text"
	JSON = "json"
	XML  = "xml"
)

type Transport interface {
	Run(command string, timeout time.Duration, cache ...bool) (result any, err error)
	Map(command string, timeout time.Duration, mapping map[string]string, cache ...bool) (result map[string]any, err error)
}
