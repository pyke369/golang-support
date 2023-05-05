package expect

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/rcache"
)

func flatten(input []any) (output any) {
	for _, element := range input {
		if fields, ok := element.(map[string]any); ok {
			data, dok := fields["data"].(string)
			attributes, aok := fields["attributes"].(map[string]any)
			if aok {
				for key, value := range attributes {
					if strings.HasPrefix(key, "xmlns") {
						delete(attributes, key)
					}
					if strings.Contains(key, ":") {
						attributes[strings.SplitN(key, ":", 2)[1]] = value
						delete(attributes, key)
					}
				}
				if len(attributes) == 0 {
					aok = false
				}
			}
			if len(fields) != 0 {
				var value any

				if dok && !aok {
					value = data
				} else {
					value = map[string]any{}
					if aok {
						for key, attribute := range attributes {
							value.(map[string]any)["@"+key] = attribute
						}
					}
					if dok {
						value.(map[string]any)["#data"] = data
					} else {
						for key, svalue := range fields {
							if _, ok := svalue.([]any); ok && key != "data" && key != "attributes" {
								if svalue := flatten(svalue.([]any)); svalue != nil {
									value.(map[string]any)[key] = svalue
								}
							}
						}
					}
				}
				if value != nil {
					if len(input) > 1 {
						if output == nil {
							output = []any{}
						}
						output = append(output.([]any), value)
					} else {
						output = value
					}
				}
			}
		}
	}
	return
}
func parseJSON(input string) (output map[string]any) {
	var raw map[string]any

	if json.Unmarshal([]byte(input), &raw) == nil {
		for key, value := range raw {
			if _, ok := value.([]any); ok {
				output = map[string]any{key: flatten(value.([]any))}
				break
			}
		}
	}
	return
}

func next(matcher *regexp.Regexp, input any, path []string) (output, parent any) {
	output, parent = input, input
	for _, part := range path {
		if captures := matcher.FindStringSubmatch(part); captures != nil {
			index, _ := strconv.Atoi(captures[1])
			if value, ok := output.([]any); !ok || index >= len(value) {
				return nil, nil
			} else {
				output = value[index]
			}
		} else {
			if value, ok := output.(map[string]any); !ok {
				return nil, nil
			} else {
				parent = output
				output = value[part]
			}
		}
	}
	return
}
func parseXML(input string) (output map[string]any) {
	type NODE struct {
		Content []byte `xml:",innerxml"`
	}
	var (
		data    []byte
		node    NODE
		matcher = rcache.Get(`^\[(\d+)\]$`)
	)

	output = map[string]any{}
	if xml.Unmarshal([]byte(input), &node) == nil {
		input = string(node.Content)
	}
	path, decoder := []string{}, xml.NewDecoder(strings.NewReader(input))
	for {
		token, err := decoder.Token()
		if err != nil || token == nil {
			break
		}
		switch node := token.(type) {
		case xml.StartElement:
			name := node.Name.Local
			if current, _ := next(matcher, output, path); current != nil {
				element := map[string]any{}
				for _, attribute := range node.Attr {
					if !strings.HasPrefix(attribute.Name.Local, "xmlns") {
						element["@"+attribute.Name.Local] = attribute.Value
					}
				}
				value1 := current.(map[string]any)
				if value1[name] == nil {
					value1[name] = element
					path = append(path, name)
				} else {
					if value2, ok := value1[name].([]any); ok {
						value2 = append(value2, element)
						value1[name] = value2
						path = append(path, []string{name, "[" + strconv.Itoa(len(value2)-1) + "]"}...)
					} else {
						value1[name] = []any{value1[name], element}
						path = append(path, []string{name, "[1]"}...)
					}
				}
			}

		case xml.EndElement:
			steps, last, index := 0, "", 0
			if len(path) >= 1 {
				steps, last = 1, path[len(path)-1]
				if captures := matcher.FindStringSubmatch(last); captures != nil && len(path) >= 2 {
					steps, last = 2, path[len(path)-2]
					index, _ = strconv.Atoi(captures[1])
				}
			}
			if current, parent := next(matcher, output, path); current != nil && steps != 0 {
				if len(data) != 0 {
					if value, ok := current.(map[string]any); ok && len(value) != 0 {
						value["#data"] = string(data)
					} else {
						if steps == 2 {
							parent.(map[string]any)[last].([]any)[index] = string(data)
						} else {
							parent.(map[string]any)[last] = string(data)
						}
					}
					data = nil
				} else {
					if value, ok := current.(map[string]any); ok && len(value) == 0 {
						if steps == 2 {
							parent.(map[string]any)[last] = parent.(map[string]any)[last].([]any)[:len(parent.(map[string]any)[last].([]any))-1]
						} else {
							delete(parent.(map[string]any), last)
						}
					}
				}
				path = path[:len(path)-steps]
			}

		case xml.CharData:
			data = bytes.TrimSpace(node.Copy())
		}
	}
	return
}

func Mapper(matcher *regexp.Regexp, input any, mapping map[string]string) (output map[string]any) {
	separator := "/"
	output = map[string]any{}
	if matcher == nil {
		matcher = rcache.Get(`^\[(-?\d+(?:,-?\d+)*|(\d+)-(\d+)|\*)\]$`)
	}
	for key, path := range mapping {
		output[key] = nil
		parts, current := strings.Split(strings.Trim(path, separator), separator), input
		last := len(parts) - 1
		for depth, part := range parts {
			part = strings.TrimSpace(part)
			if len(part) == 0 {
				continue
			}
			if captures := matcher.FindStringSubmatch(part); captures != nil {
				if next, ok := current.([]any); ok {
					output[key] = []any{}
					length, indexes := len(next), []int{}
					if captures[1] == "*" {
						for index := 0; index < length; index++ {
							indexes = append(indexes, index)
						}
					} else {
						if captures[2] != "" && captures[3] != "" {
							start, _ := strconv.Atoi(captures[2])
							end, _ := strconv.Atoi(captures[3])
							if end >= len(next) {
								end = len(next) - 1
							}
							if start <= end {
								for index := start; index <= end; index++ {
									indexes = append(indexes, index)
								}
							}
						} else {
							for _, value := range strings.Split(captures[1], ",") {
								if index, err := strconv.Atoi(value); err == nil {
									if index < 0 {
										index = len(next) + index
									}
									if index >= 0 && index < len(next) {
										indexes = append(indexes, index)
									}
								}
							}
						}
					}
					for _, index := range indexes {
						if depth == last {
							output[key] = append(output[key].([]any), next[index])
						} else {
							output[key] = append(output[key].([]any), Mapper(
								matcher, next[index],
								map[string]string{"_": strings.Join(parts[depth+1:], separator)})["_"])
						}
					}
					break
				} else if next, ok := current.(map[string]any); ok {
					output[key] = []any{}
					output[key] = append(output[key].([]any), Mapper(
						matcher, next,
						map[string]string{"_": strings.Join(parts[depth+1:], separator)})["_"])
					break
				} else {
					break
				}
			} else {
				if next, ok := current.(map[string]any); ok {
					if part[0] == '~' {
						if matcher := rcache.Get(strings.TrimSpace(part[1:])); matcher != nil {
							indexes := []string{}
							for index := range next {
								if matcher.MatchString(index) {
									indexes = append(indexes, index)
								}
							}
							if len(indexes) > 1 {
								output[key] = []any{}
							}
							for _, index := range indexes {
								if depth == last {
									if len(indexes) > 1 {
										output[key] = append(output[key].([]any), next[index])
									} else {
										output[key] = next[index]
									}
								} else {
									if len(indexes) > 1 {
										output[key] = append(output[key].([]any), Mapper(
											matcher, next[index],
											map[string]string{"_": strings.Join(parts[depth+1:], separator)})["_"])
									} else {
										output[key] = Mapper(
											matcher, next[index],
											map[string]string{"_": strings.Join(parts[depth+1:], separator)})["_"]
									}
								}
							}
						}
						break
					} else {
						if _, ok := next[part]; ok {
							if depth == last {
								output[key] = next[part]
								break
							} else {
								current = next[part]
							}
						} else {
							break
						}
					}
				} else {
					break
				}
			}
		}
	}
	return
}
