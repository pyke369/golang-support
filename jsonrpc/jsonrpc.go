package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type CONTEXT_KEY string

type CALL struct {
	Method       string
	Params       any
	Notification bool
	Result       any
	Error        *ERROR
	Id           string
	id           string
	paired       bool
}
type TRANSPORT_OPTIONS struct {
	URL       string
	Headers   map[string]string
	Timeout   time.Duration
	Context   any
	Transport *http.Transport
}
type TRANSPORT func([]byte, any) ([]byte, error)

type REQUEST struct {
	JSONRPC string
	Id      any
	Method  string
	Params  any
}
type RESPONSE struct {
	Id     any
	Result any
	Error  *ERROR
}
type ERROR struct {
	Code    int
	Message string
	Data    any
}
type ROUTE struct {
	Handler HANDLER
	Opaque  any
}
type HANDLER func(map[string]any, any) (any, *ERROR)

var httpDefaultTransport *http.Transport

func init() {
	httpDefaultTransport = http.DefaultTransport.(*http.Transport).Clone()
	httpDefaultTransport.MaxIdleConnsPerHost = 64
	httpDefaultTransport.IdleConnTimeout = 60 * time.Second
	httpDefaultTransport.DisableCompression = true
}

func DefaultTransport(input []byte, tcontext any) (output []byte, err error) {
	options := tcontext.(TRANSPORT_OPTIONS)
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
			request = request.WithContext(context.WithValue(request.Context(), CONTEXT_KEY("jsonrpc"), options.Context))
		}
		for key, value := range options.Headers {
			request.Header.Set(key, value)
		}
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: options.Transport, Timeout: options.Timeout}
		if response, err := client.Do(request); err == nil {
			output, _ = io.ReadAll(response.Body)
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

func Request(calls []*CALL) (payload []byte, err error) {
	payload = make([]byte, 0, 128)
	if len(calls) > 1 {
		payload = append(payload, '[')
	}
	for index, call := range calls {
		if call.Method == "" {
			return nil, fmt.Errorf("jsonrpc: invalid method for call #%d", index)
		}
		call.id, call.paired = call.Id, false
		if call.Notification {
			call.id = ""
		} else if call.Id == "" {
			call.id = uuid.UUID()
		}
		payload = append(payload, `{"jsonrpc":"2.0","method":"`...)
		payload = append(payload, call.Method...)
		payload = append(payload, '"')
		if !call.Notification {
			payload = append(payload, `,"id":"`...)
			payload = append(payload, call.id...)
			payload = append(payload, '"')
		}
		if call.Params != nil {
			if marshaled, err := json.Marshal(call.Params); err == nil {
				payload = append(payload, `,"params":`...)
				if marshaled[0] != '[' && marshaled[0] != '{' {
					payload = append(payload, '[')
					payload = append(payload, marshaled...)
					payload = append(payload, ']')
				} else {
					payload = append(payload, marshaled...)
				}
			}
		}
		payload = append(payload, '}')
		if index < len(calls)-1 {
			payload = append(payload, ',')
		}
	}
	if len(calls) > 1 {
		payload = append(payload, ']')
	}
	return
}

func Response(payload []byte, calls []*CALL) (results []*CALL, err error) {
	if payload == nil {
		payload = []byte("[]")
	}
	payload = bytes.TrimSpace(payload)
	if payload[0] != '[' {
		payload = append([]byte("["), payload...)
		payload = append(payload, ']')
	}
	responses, ids := []RESPONSE{}, map[string]*CALL{}
	if err := json.Unmarshal(payload, &responses); err != nil {
		return nil, fmt.Errorf("jsonrpc: %v", err)
	}
	if calls == nil {
		calls = []*CALL{}
	}
	for _, call := range calls {
		if call.id != "" {
			ids[call.id] = call
		}
	}
	for _, response := range responses {
		id := fmt.Sprintf("%v", response.Id)
		if len(ids) != 0 {
			if call, ok := ids[id]; ok {
				call.Result, call.Error, call.paired = response.Result, response.Error, true
			}
		} else {
			calls = append(calls, &CALL{Id: id, Result: response.Result, Error: response.Error})
		}
	}
	if len(ids) != 0 {
		for _, call := range calls {
			if !call.Notification && !call.paired {
				call.Error = &ERROR{Code: INTERNAL_ERROR_CODE, Message: INTERNAL_ERROR_MESSAGE}
			}
		}
	}
	return calls, nil
}

func Call(calls []*CALL, transport TRANSPORT, tcontext any) (results []*CALL, err error) {
	if len(calls) == 0 {
		return nil, errors.New(`jsonrpc: no call provided`)
	}
	if transport == nil {
		if _, ok := tcontext.(TRANSPORT_OPTIONS); !ok {
			return nil, errors.New(`jsonrpc: invalid context for default transport`)
		}
		transport = DefaultTransport
	}
	input, err := Request(calls)
	if err != nil {
		return nil, err
	}
	output, err := transport(input, tcontext)
	if err != nil {
		return nil, err
	}
	return Response(output, calls)
}

func Handle(input []byte, routes map[string]*ROUTE, filters []string, options ...any) (output []byte) {
	input = bytes.TrimSpace(input)
	output = []byte{}
	batch := true
	requests, responses := []REQUEST{}, map[any]*RESPONSE{}
	if len(input) == 0 {
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
			if len(requests) == 0 || len(requests) > 1024 || requests[0].JSONRPC == "" {
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
							params := map[string]any{}
							for index, value := range request.Params.([]any) {
								params[fmt.Sprintf("_%d", index)] = value
							}
							request.Params = params
						}
					} else {
						request.Params = map[string]any{}
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
						if result, err := routes[request.Method].Handler(request.Params.(map[string]any), opaque); err != nil {
							sink <- &RESPONSE{Id: request.Id, Error: err}
						} else {
							sink <- &RESPONSE{Id: request.Id, Result: result}
						}
					}(request)
				}
				for running > 0 {
					response := <-sink
					if response.Id != nil {
						responses[response.Id] = response
					}
					running--
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

func Bool(input any) bool {
	if cast, ok := input.(bool); ok {
		return cast
	}
	return false
}
func String(input any) string {
	if cast, ok := input.(string); ok {
		return cast
	}
	return ""
}
func Number(input any) float64 {
	if input != nil {
		switch reflect.TypeOf(input).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return float64(reflect.ValueOf(input).Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return float64(reflect.ValueOf(input).Uint())
		case reflect.Float32, reflect.Float64:
			return reflect.ValueOf(input).Float()
		}
	}
	return 0.0
}

func Slice(input any) []any {
	if cast, ok := input.([]any); ok {
		return cast
	}
	return []any{}
}
func SliceItem(input []any, index int) any {
	if index >= len(input) {
		return nil
	}
	return input[index]
}
func StringSlice(input any, extra ...bool) (output []string) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := input.([]string); ok {
		if !noempty {
			return cast
		}
		output = []string{}
		for _, item := range cast {
			if strings.TrimSpace(item) != "" {
				output = append(output, item)
			}
		}
		return
	}
	output = []string{}
	if cast, ok := input.([]any); ok {
		for _, item := range cast {
			value := String(item)
			if !noempty || strings.TrimSpace(value) != "" {
				output = append(output, value)
			}
		}
	}
	return
}
func StringSliceItem(input []string, index int) string {
	if index >= len(input) {
		return ""
	}
	return input[index]
}
func NumberSlice(input any, extra ...bool) (output []float64) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := input.([]float64); ok {
		if !noempty {
			return cast
		}
		output = []float64{}
		for _, value := range cast {
			if value != 0 {
				output = append(output, value)
			}
		}
		return
	}
	output = []float64{}
	if cast, ok := input.([]any); ok {
		for _, item := range cast {
			value := Number(item)
			if !noempty || value != 0 {
				output = append(output, value)
			}
		}
	}
	return
}
func NumberSliceItem(input []float64, index int) float64 {
	if index >= len(input) {
		return 0.0
	}
	return input[index]
}

func Map(input any) map[string]any {
	if cast, ok := input.(map[string]any); ok {
		return cast
	}
	return map[string]any{}
}
func StringMap(input any, extra ...bool) (output map[string]string) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := input.(map[string]string); ok {
		if !noempty {
			return cast
		}
		output = map[string]string{}
		for key, value := range cast {
			if strings.TrimSpace(value) != "" {
				output[key] = value
			}
		}
		return
	}
	output = map[string]string{}
	if cast, ok := input.(map[string]any); ok {
		for key, item := range cast {
			value := String(item)
			if !noempty || strings.TrimSpace(value) != "" {
				output[key] = value
			}
		}
	}
	return
}
func NumberMap(input any, extra ...bool) (output map[string]float64) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := input.(map[string]float64); ok {
		if !noempty {
			return cast
		}
		output = map[string]float64{}
		for key, value := range cast {
			if value != 0 {
				output[key] = value
			}
		}
		return
	}
	output = map[string]float64{}
	if cast, ok := input.(map[string]any); ok {
		for key, item := range cast {
			value := Number(item)
			if !noempty || value != 0 {
				output[key] = value
			}
		}
	}
	return
}
