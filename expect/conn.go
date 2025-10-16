package expect

const (
	TEXT = "text"
	JSON = "json"
	XML  = "xml"
)

type Conn interface {
	Run(string, ...map[string]any) (any, error)
	Map(string, map[string]string, ...map[string]any) (map[string]any, error)
	Close()
}
