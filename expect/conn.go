package expect

import (
	"time"
)

const (
	TEXT = "text"
	JSON = "json"
	XML  = "xml"
)

type Conn interface {
	Run(command string, timeout ...time.Duration) (result any, err error)
	Map(command string, mapping map[string]string, timeout ...time.Duration) (result map[string]any, err error)
	Close()
}
