package jsonrpc

import (
	"bytes"
	gcontext "context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uuid"
)

const (
	LOW_RESERVED_CODE             = -32768
	HIGH_RESERVED_CODE            = -32000
	PARSE_ERROR_CODE              = -32700
	PARSE_ERROR_MESSAGE           = "parse error"
	INVALID_REQUEST_CODE          = -32600
	INVALID_REQUEST_MESSAGE       = "invalid request"
	METHOD_NOT_FOUND_CODE         = -32601
	METHOD_NOT_FOUND_MESSAGE      = "method not found"
	METHOD_NOT_AUTHORIZED_CODE    = -32601
	METHOD_NOT_AUTHORIZED_MESSAGE = "method not authorized"
	INVALID_PARAMS_CODE           = -32602
	INVALID_PARAMS_MESSAGE        = "invalid params"
	INTERNAL_ERROR_CODE           = -32603
	INTERNAL_ERROR_MESSAGE        = "internal error"
)

type CALL struct {
	Method       string
	Params       interface{}
	Notification bool
	Result       interface{}
	Error        *ERROR
	Id           string
	paired       bool
}
type TRANSPORT_OPTIONS struct {
	URL       string
	Headers   map[string]string
	Timeout   time.Duration
	Context   interface{}
	Transport *http.Transport
}
type TRANSPORT func([]byte, interface{}) ([]byte, error)

type REQUEST struct {
	JSONRPC string
	Id      interface{}
	Method  string
	Params  interface{}
}
type RESPONSE struct {
	Id     interface{}
	Result interface{}
	Error  *ERROR
}
type ERROR struct {
	Code    int
	Message string
	Data    interface{}
}
type ROUTE struct {
	Handler HANDLER
	Opaque  interface{}
}
type HANDLER func(map[string]interface{}, interface{}) (interface{}, *ERROR)

var httpDefaultTransport *http.Transport

func init() {
	httpDefaultTransport = http.DefaultTransport.(*http.Transport).Clone()
	httpDefaultTransport.MaxIdleConnsPerHost = 64
	httpDefaultTransport.IdleConnTimeout = 60 * time.Second
	httpDefaultTransport.DisableCompression = true
}

func DefaultTransport(input []byte, context interface{}) (output []byte, err error) {
	options := context.(TRANSPORT_OPTIONS)
	if options.URL == "" {
		return nil, errors.New(`jsonrpc: missing URL in default transport options`)
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.Timeout < 100*time.Millisecond {
		options.Timeout = 100 * time.Millisecond
	}
	if options.Transport == nil {
		options.Transport = httpDefaultTransport
	}
	if request, err := http.NewRequest("POST", options.URL, bytes.NewBuffer(input)); err == nil {
		if options.Context != nil {
			request = request.WithContext(gcontext.WithValue(request.Context(), "jsonrpc", options.Context))
		}
		for key, value := range options.Headers {
			request.Header.Set(key, value)
		}
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: options.Transport, Timeout: options.Timeout}
		if response, err := client.Do(request); err == nil {
			output, _ = ioutil.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode/100 != 2 || len(output) == 0 {
				return nil, fmt.Errorf("jsonrpc: HTTP error %d", response.StatusCode)
			}
		} else {
			return nil, fmt.Errorf("jsonrpc: %v", err)
		}
	} else {
		return nil, fmt.Errorf("jsonrpc: %v", err)
	}
	return
}

func Call(calls []*CALL, transport TRANSPORT, context interface{}) (results []*CALL, err error) {
	if calls == nil || len(calls) == 0 {
		return nil, errors.New(`jsonrpc: no call provided`)
	}
	if transport == nil {
		if _, ok := context.(TRANSPORT_OPTIONS); !ok {
			return nil, errors.New(`jsonrpc: invalid context for default transport`)
		}
		transport = DefaultTransport
	}
	input, ids := make([]byte, 0, 128), map[string]*CALL{}
	if len(calls) > 1 {
		input = append(input, '[')
	}
	for index, call := range calls {
		if call.Method == "" {
			return nil, fmt.Errorf("jsonrpc: invalid method for call #%d", index)
		}
		if call.Notification {
			call.Id = ""
		} else if call.Id == "" {
			call.Id = uuid.UUID()
		}
		if call.Id != "" {
			ids[call.Id] = call
		}
		input = append(input, `{"jsonrpc":"2.0","method":"`...)
		input = append(input, call.Method...)
		input = append(input, '"')
		if !call.Notification {
			input = append(input, `,"id":"`...)
			input = append(input, call.Id...)
			input = append(input, '"')
		}
		if call.Params != nil {
			if marshaled, err := json.Marshal(call.Params); err == nil {
				input = append(input, `,"params":`...)
				if marshaled[0] != '[' && marshaled[0] != '{' {
					input = append(input, '[')
					input = append(input, marshaled...)
					input = append(input, ']')
				} else {
					input = append(input, marshaled...)
				}
			}
		}
		input = append(input, '}')
		if index < len(calls)-1 {
			input = append(input, ',')
		}
	}
	if len(calls) > 1 {
		input = append(input, ']')
	}
	if output, err := transport(input, context); err != nil {
		return nil, err
	} else {
		if output == nil {
			output = []byte("[]")
		}
		output = bytes.TrimSpace(output)
		if output[0] != '[' {
			output = append([]byte("["), output...)
			output = append(output, ']')
		}
		responses := []RESPONSE{}
		if err := json.Unmarshal(output, &responses); err == nil {
			for _, response := range responses {
				if call, ok := ids[fmt.Sprintf("%v", response.Id)]; ok {
					call.Result, call.Error, call.paired = response.Result, response.Error, true
				}
			}
			for _, call := range calls {
				if !call.Notification && !call.paired {
					call.Error = &ERROR{Code: INTERNAL_ERROR_CODE, Message: INTERNAL_ERROR_MESSAGE}
				}
			}
			results = calls
		} else {
			return nil, fmt.Errorf("jsonrpc: %v", err)
		}
	}
	return
}

func Handle(input []byte, routes map[string]*ROUTE, filters []string, options ...interface{}) (output []byte) {
	input = bytes.TrimSpace(input)
	output = []byte{}
	batch := true
	requests, responses := []REQUEST{}, map[interface{}]*RESPONSE{}
	if input == nil || len(input) == 0 {
		responses[true] = &RESPONSE{Error: &ERROR{Code: PARSE_ERROR_CODE, Message: PARSE_ERROR_MESSAGE}}
	} else {
		if input[0] != '[' {
			batch = false
			input = append([]byte{'['}, input...)
			input = append(input, ']')
		}
		if json.Unmarshal(input, &requests) != nil {
			responses[true] = &RESPONSE{Error: &ERROR{Code: PARSE_ERROR_CODE, Message: PARSE_ERROR_MESSAGE}}
		} else {
			if len(requests) == 0 || len(requests) > 1024 {
				responses[true] = &RESPONSE{Error: &ERROR{Code: INVALID_REQUEST_CODE, Message: INVALID_REQUEST_MESSAGE}}
			} else {
				running, sink := 0, make(chan *RESPONSE, 1024)
				for _, request := range requests {
					_, ok1 := request.Id.(string)
					_, ok2 := request.Id.(float64)
					if request.JSONRPC != "2.0" || request.Method == "" || (request.Id != nil && !ok1 && !ok2) {
						if request.Id != nil && (ok1 || ok2) {
							responses[request.Id] = &RESPONSE{Id: request.Id, Error: &ERROR{Code: INVALID_REQUEST_CODE, Message: INVALID_REQUEST_MESSAGE}}
						}
						continue
					}
					if routes == nil || routes[request.Method] == nil {
						if request.Id != nil {
							responses[request.Id] = &RESPONSE{Id: request.Id, Error: &ERROR{Code: METHOD_NOT_FOUND_CODE, Message: METHOD_NOT_FOUND_MESSAGE}}
						}
						continue
					}
					if len(filters) != 0 {
						authorized := false
						for _, filter := range filters {
							if filter = strings.TrimSpace(filter); len(filter) != 0 {
								if filter[0] == '~' {
									if matcher := rcache.Get(strings.TrimSpace(filter[1:])); matcher != nil && matcher.MatchString(request.Method) {
										authorized = true
										break
									}
								} else if filter[0] == '=' {
									if request.Method == strings.TrimSpace(filter[1:]) {
										authorized = true
										break
									}
								} else {
									if strings.Contains(request.Method, filter) {
										authorized = true
										break
									}
								}
							}
						}
						if !authorized {
							if request.Id != nil {
								responses[request.Id] = &RESPONSE{Id: request.Id, Error: &ERROR{Code: METHOD_NOT_AUTHORIZED_CODE, Message: METHOD_NOT_AUTHORIZED_MESSAGE}}
							}
							continue
						}
					}
					if request.Params != nil {
						if kind := reflect.TypeOf(request.Params).Kind(); kind != reflect.Slice && kind != reflect.Map {
							if request.Id != nil {
								responses[request.Id] = &RESPONSE{Id: request.Id, Error: &ERROR{Code: INVALID_REQUEST_CODE, Message: INVALID_REQUEST_MESSAGE}}
							}
							continue
						} else if kind == reflect.Slice {
							params := map[string]interface{}{}
							for index, value := range request.Params.([]interface{}) {
								params[fmt.Sprintf("_%d", index)] = value
							}
							request.Params = params
						}
					} else {
						request.Params = map[string]interface{}{}
					}
					running++
					go func(request REQUEST) {
						defer func() {
							if r := recover(); r != nil {
								sink <- &RESPONSE{Id: request.Id, Error: &ERROR{Code: INTERNAL_ERROR_CODE, Message: INTERNAL_ERROR_MESSAGE, Data: fmt.Sprintf("jsonrpc: %v", r)}}
							}
						}()
						opaque := routes[request.Method].Opaque
						if opaque == nil && len(options) > 0 {
							opaque = options[0]
						}
						if result, err := routes[request.Method].Handler(request.Params.(map[string]interface{}), opaque); err != nil {
							sink <- &RESPONSE{Id: request.Id, Error: err}
						} else {
							sink <- &RESPONSE{Id: request.Id, Result: result}
						}
					}(request)
				}
				for running > 0 {
					select {
					case response := <-sink:
						if response.Id != nil {
							responses[response.Id] = response
						}
						running--
					}
				}
				close(sink)
			}
		}
	}
	if response := responses[true]; response != nil && response.Error != nil {
		output = append(output, `{"jsonrpc":"2.0","error":{"code":`...)
		output = strconv.AppendInt(output, int64(response.Error.Code), 10)
		output = append(output, `,"message":"`...)
		output = append(output, response.Error.Message...)
		output = append(output, '"')
		if response.Error.Data != nil {
			if data, err := json.Marshal(response.Error.Data); err == nil {
				output = append(output, `,"data":`...)
				output = append(output, data...)
			}
		}
		output = append(output, `}}`...)
		return output
	}
	if batch {
		output = append(output, '[')
	}
	index := 0
	for id, response := range responses {
		output = append(output, `{"jsonrpc":"2.0","id":`...)
		if _, ok := id.(float64); ok {
			output = strconv.AppendInt(output, int64(id.(float64)), 10)
		} else if _, ok := id.(string); ok {
			output = append(output, '"')
			output = append(output, id.(string)...)
			output = append(output, '"')
		}
		output = append(output, ',')
		if response.Error != nil {
			output = append(output, `"error":{"code":`...)
			output = strconv.AppendInt(output, int64(response.Error.Code), 10)
			output = append(output, `,"message":"`...)
			output = append(output, response.Error.Message...)
			output = append(output, '"')
			if response.Error.Data != nil {
				if data, err := json.Marshal(response.Error.Data); err == nil {
					output = append(output, `,"data":`...)
					output = append(output, data...)
				}
			}
			output = append(output, '}')
		} else {
			output = append(output, `"result":`...)
			if result, err := json.Marshal(response.Result); err == nil {
				output = append(output, result...)
			} else {
				output = append(output, `null`...)
			}
		}
		output = append(output, '}')
		if index < len(responses)-1 {
			output = append(output, ',')
		}
		index++
	}
	if batch {
		output = append(output, ']')
	}
	return output
}

func Bool(value interface{}) bool {
	if _, ok := value.(bool); ok {
		return value.(bool)
	}
	return false
}
func String(value interface{}) string {
	if _, ok := value.(string); ok {
		return value.(string)
	}
	return ""
}
func Number(value interface{}) float64 {
	if value != nil {
		switch reflect.TypeOf(value).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return float64(reflect.ValueOf(value).Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return float64(reflect.ValueOf(value).Uint())
		case reflect.Float32, reflect.Float64:
			return reflect.ValueOf(value).Float()
		}
	}
	return 0.0
}

func Slice(value interface{}) []interface{} {
	if _, ok := value.([]interface{}); ok {
		return value.([]interface{})
	}
	return []interface{}{}
}
func StringSlice(value interface{}) []string {
	if cast, ok := value.([]string); ok {
		return cast
	}
	returned := []string{}
	if _, ok := value.([]interface{}); ok {
		for _, item := range value.([]interface{}) {
			if _, ok := item.(string); ok {
				returned = append(returned, item.(string))
			}
		}
	}
	return returned
}
func NumberSlice(value interface{}) []float64 {
	if cast, ok := value.([]float64); ok {
		return cast
	}
	returned := []float64{}
	if _, ok := value.([]interface{}); ok {
		for _, item := range value.([]interface{}) {
			if _, ok := item.(float64); ok {
				returned = append(returned, item.(float64))
			}
		}
	}
	return returned
}

func Map(value interface{}) map[string]interface{} {
	if _, ok := value.(map[string]interface{}); ok {
		return value.(map[string]interface{})
	}
	return map[string]interface{}{}
}
func StringMap(value interface{}) map[string]string {
	if cast, ok := value.(map[string]string); ok {
		return cast
	}
	returned := map[string]string{}
	if _, ok := value.(map[string]interface{}); ok {
		for key, item := range value.(map[string]interface{}) {
			if _, ok := item.(string); ok {
				returned[key] = item.(string)
			}
		}
	}
	return returned
}
func NumberMap(value interface{}) map[string]float64 {
	if cast, ok := value.(map[string]float64); ok {
		return cast
	}
	returned := map[string]float64{}
	if _, ok := value.(map[string]interface{}); ok {
		for key, item := range value.(map[string]interface{}) {
			if _, ok := item.(float64); ok {
				returned[key] = item.(float64)
			}
		}
	}
	return returned
}
