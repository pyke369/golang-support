package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
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
	Context any
}
type HANDLER func(map[string]any, any) (any, *ERROR)

var httpDefaultTransport *http.Transport

func init() {
	httpDefaultTransport = http.DefaultTransport.(*http.Transport).Clone()
	httpDefaultTransport.MaxIdleConnsPerHost = 64
	httpDefaultTransport.IdleConnTimeout = 60 * time.Second
	httpDefaultTransport.DisableCompression = true
}

func DefaultTransport(in []byte, tcontext any) (out []byte, err error) {
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
	if request, err := http.NewRequest("POST", options.URL, bytes.NewBuffer(in)); err == nil {
		if options.Context != nil {
			request = request.WithContext(context.WithValue(request.Context(), CONTEXT_KEY("jsonrpc"), options.Context))
		}
		for key, value := range options.Headers {
			request.Header.Set(key, value)
		}
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: options.Transport, Timeout: options.Timeout}
		if response, err := client.Do(request); err == nil {
			out, _ = io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode/100 != 2 || len(out) == 0 {
				return nil, errors.New("jsonrpc: HTTP error " + strconv.Itoa(response.StatusCode))
			}
		} else {
			return nil, ustr.Wrap(err, "jsonrpc")
		}
	} else {
		return nil, ustr.Wrap(err, "jsonrpc")
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
			return nil, errors.New("jsonrpc: invalid method for call #" + strconv.Itoa(index))
		}
		call.id, call.paired = call.Id, false
		if call.Notification {
			call.id = ""
		} else if call.Id == "" {
			call.id = uuid.New().String()
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
		return nil, ustr.Wrap(err, "jsonrpc")
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
		id := String(response.Id)
		if value := Number(response.Id); value != 0 {
			id = strconv.FormatInt(int64(value), 10)
		}
		if len(ids) != 0 {
			if call, exists := ids[id]; exists {
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
	in, err := Request(calls)
	if err != nil {
		return nil, err
	}
	out, err := transport(in, tcontext)
	if err != nil {
		return nil, err
	}
	return Response(out, calls)
}

func Handle(in []byte, routes map[string]*ROUTE, filter func(string, any) bool, extra ...any) (out []byte) {
	in = bytes.TrimSpace(in)
	out = []byte{}
	batch := true
	requests, responses := []REQUEST{}, map[any]*RESPONSE{}
	if len(in) == 0 {
		responses[true] = &RESPONSE{Error: &ERROR{Code: PARSE_ERROR_CODE, Message: PARSE_ERROR_MESSAGE}}
	} else {
		if in[0] != '[' {
			batch = false
			in = append([]byte{'['}, in...)
			in = append(in, ']')
		}
		if json.Unmarshal(in, &requests) != nil {
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

					if filter != nil {
						ctx := routes[request.Method].Context
						if ctx == nil && len(extra) > 0 {
							ctx = extra[0]
						}
						if filter(request.Method, ctx) {
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
								params["_"+strconv.Itoa(index)] = value
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
								err := errors.New("unknown")
								if value, ok := r.(error); ok {
									err = value
								}
								if value, ok := r.(string); ok {
									err = errors.New(value)
								}
								sink <- &RESPONSE{Id: request.Id, Error: &ERROR{Code: INTERNAL_ERROR_CODE, Message: INTERNAL_ERROR_MESSAGE, Data: ustr.Wrap(err, "jsonrpc").Error()}}
							}
						}()

						ctx := routes[request.Method].Context
						if ctx == nil && len(extra) > 0 {
							ctx = extra[0]
						}
						if result, err := routes[request.Method].Handler(request.Params.(map[string]any), ctx); err != nil {
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
		out = append(out, `{"jsonrpc":"2.0","error":{"code":`...)
		out = strconv.AppendInt(out, int64(response.Error.Code), 10)
		out = append(out, `,"message":"`...)
		out = append(out, response.Error.Message...)
		out = append(out, '"')
		if response.Error.Data != nil {
			if data, err := json.Marshal(response.Error.Data); err == nil {
				out = append(out, `,"data":`...)
				out = append(out, data...)
			}
		}
		out = append(out, `}}`...)
		return out
	}
	if batch {
		out = append(out, '[')
	}
	index := 0
	for id, response := range responses {
		out = append(out, `{"jsonrpc":"2.0","id":`...)
		if value, ok := id.(float64); ok {
			out = strconv.AppendInt(out, int64(value), 10)
		}
		if value, ok := id.(string); ok {
			out = append(out, '"')
			out = append(out, value...)
			out = append(out, '"')
		}
		out = append(out, ',')
		if response.Error != nil {
			out = append(out, `"error":{"code":`...)
			out = strconv.AppendInt(out, int64(response.Error.Code), 10)
			out = append(out, `,"message":"`...)
			out = append(out, response.Error.Message...)
			out = append(out, '"')
			if response.Error.Data != nil {
				if data, err := json.Marshal(response.Error.Data); err == nil {
					out = append(out, `,"data":`...)
					out = append(out, data...)
				}
			}
			out = append(out, '}')
		} else {
			out = append(out, `"result":`...)
			if result, err := json.Marshal(response.Result); err == nil {
				out = append(out, result...)
			} else {
				out = append(out, `null`...)
			}
		}
		out = append(out, '}')
		if index < len(responses)-1 {
			out = append(out, ',')
		}
		index++
	}
	if batch {
		out = append(out, ']')
	}
	return out
}

func Boolean(in any) bool {
	if cast, ok := in.(bool); ok {
		return cast
	}
	if value, ok := in.(int); ok {
		return value > 0
	}
	if value, ok := in.(string); ok {
		if value = strings.TrimSpace(value); value != "" {
			asn, _ := strconv.Atoi(value)
			if asn > 0 || strings.EqualFold(value, "true") || strings.EqualFold(value, "y") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on") {
				return true
			}
		}
		return false
	}
	return false
}
func String(in any) string {
	if cast, ok := in.(string); ok {
		return cast
	}
	return ""
}
func Number(in any, fallback ...float64) float64 {
	if in != nil {
		switch reflect.TypeOf(in).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return float64(reflect.ValueOf(in).Int())

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return float64(reflect.ValueOf(in).Uint())

		case reflect.Float32, reflect.Float64:
			return reflect.ValueOf(in).Float()

		case reflect.String:
			if value, err := strconv.ParseFloat(reflect.ValueOf(in).String(), 64); err == nil {
				return value
			}
		}
		if len(fallback) == 0 {
			if value, ok := in.(bool); ok && value {
				return 1.0
			}
		}
	}
	if len(fallback) != 0 {
		return fallback[0]
	}
	return 0.0
}

func Slice(in any) (out []any) {
	if cast, ok := in.([]any); ok {
		return cast
	}
	if value := reflect.ValueOf(in); value.Kind() == reflect.Slice {
		out = make([]any, value.Len())
		for index := 0; index < value.Len(); index++ {
			out[index] = value.Index(index).Interface()
		}
		return
	}
	return []any{}
}
func SliceItem(in []any, index int) any {
	if index >= len(in) {
		return nil
	}
	return in[index]
}
func StringSlice(in any, extra ...bool) (out []string) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := in.([]string); ok {
		if !noempty {
			return cast
		}
		out = []string{}
		for _, item := range cast {
			if strings.TrimSpace(item) != "" {
				out = append(out, item)
			}
		}
		return
	}
	out = []string{}
	if cast, ok := in.([]any); ok {
		for _, item := range cast {
			value := String(item)
			if !noempty || strings.TrimSpace(value) != "" {
				out = append(out, value)
			}
		}
	}
	return
}
func StringSliceItem(in []string, index int) string {
	if index >= len(in) {
		return ""
	}
	return in[index]
}
func NumberSlice(in any, extra ...bool) (out []float64) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := in.([]float64); ok {
		if !noempty {
			return cast
		}
		out = []float64{}
		for _, value := range cast {
			if value != 0 {
				out = append(out, value)
			}
		}
		return
	}
	out = []float64{}
	if cast, ok := in.([]any); ok {
		for _, item := range cast {
			value := Number(item)
			if !noempty || value != 0 {
				out = append(out, value)
			}
		}
	}
	return
}
func NumberSliceItem(in []float64, index int) float64 {
	if index >= len(in) {
		return 0.0
	}
	return in[index]
}

func Map(in any) (out map[string]any) {
	if cast, ok := in.(map[string]any); ok {
		return cast
	}
	if value := reflect.ValueOf(in); value.Kind() == reflect.Map {
		out = make(map[string]any, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			out[iterator.Key().String()] = iterator.Value().Interface()
		}
		return
	}
	return map[string]any{}
}
func StringMap(in any, extra ...bool) (out map[string]string) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := in.(map[string]string); ok {
		if !noempty {
			return cast
		}
		out = map[string]string{}
		for key, value := range cast {
			if strings.TrimSpace(value) != "" {
				out[key] = value
			}
		}
		return
	}
	out = map[string]string{}
	if cast, ok := in.(map[string]any); ok {
		for key, item := range cast {
			value := String(item)
			if !noempty || strings.TrimSpace(value) != "" {
				out[key] = value
			}
		}
	}
	return
}
func NumberMap(in any, extra ...bool) (out map[string]float64) {
	noempty := len(extra) > 0 && extra[0]
	if cast, ok := in.(map[string]float64); ok {
		if !noempty {
			return cast
		}
		out = map[string]float64{}
		for key, value := range cast {
			if value != 0 {
				out[key] = value
			}
		}
		return
	}
	out = map[string]float64{}
	if cast, ok := in.(map[string]any); ok {
		for key, item := range cast {
			value := Number(item)
			if !noempty || value != 0 {
				out[key] = value
			}
		}
	}
	return
}
func IntegerMap(in any, extra ...bool) (out map[string]int) {
	out = map[string]int{}
	for key, value := range NumberMap(in, extra...) {
		out[key] = int(value)
	}
	return
}

func KeysLength(in any) (out int) {
	for key := range Map(in) {
		out = max(len(key), out)
	}
	return
}
func MapKeys(in any) (out []string) {
	for key := range Map(in) {
		out = append(out, key)
	}
	sort.Strings(out)
	return
}
func SwitchMap(in map[string]string) (out map[string]string) {
	out = map[string]string{}
	for key, value := range in {
		out[value] = key
	}
	return
}

func Size(in string, fallback int64, extra ...bool) int64 {
	return SizeBounds(in, fallback, 0, math.MaxInt64, extra...)
}
func SizeBounds(in string, fallback, lowest, highest int64, extra ...bool) (out int64) {
	if captures := rcache.Get(`^(\d+(?:\.\d*)?)\s*([KMGTP]?)(B?)$`).FindStringSubmatch(strings.TrimSpace(strings.ToUpper(in))); captures != nil {
		value, err := strconv.ParseFloat(captures[1], 64)
		if err != nil {
			return fallback
		}
		scale := float64(1000)
		if captures[3] == "B" || (len(extra) != 0 && extra[0]) {
			scale = float64(1024)
		}
		out = int64(value * math.Pow(scale, float64(strings.Index("_KMGTP", captures[2]))))
	} else {
		return fallback
	}
	return max(min(out, highest), max(0, lowest))
}

func Duration(in string, fallback float64) time.Duration {
	return DurationBounds(in, fallback, 0, math.MaxFloat64)
}
func DurationBounds(in string, fallback, lowest, highest float64) (out time.Duration) {
	in = strings.TrimSpace(in)

	value := float64(0.0)
	if captures := rcache.Get(`(\d+)(Y|MO|D|H|MN|S|MS|US)?`).FindAllStringSubmatch(strings.ToUpper(in), -1); captures != nil {
		for index := 0; index < len(captures); index++ {
			if uvalue, err := strconv.ParseFloat(captures[index][1], 64); err == nil {
				switch captures[index][2] {
				case "Y":
					value += uvalue * 86400 * 365.256

				case "MO":
					value += uvalue * 86400 * 365.256 / 12

				case "D":
					value += uvalue * 86400

				case "H":
					value += uvalue * 3600

				case "MN":
					value += uvalue * 60

				case "S":
					value += uvalue

				case "":
					value += uvalue

				case "MS":
					value += uvalue / 1000

				case "US":
					value += uvalue / 1000000
				}
			}
		}
	} else if captures := rcache.Get(`^(?:(\d+):)?(\d{2}):(\d{2})(?:\.(\d{1,3}))?$`).FindStringSubmatch(in); captures != nil {
		hours, _ := strconv.ParseFloat(captures[1], 64)
		minutes, _ := strconv.ParseFloat(captures[2], 64)
		seconds, _ := strconv.ParseFloat(captures[3], 64)
		milliseconds, _ := strconv.ParseFloat(captures[4], 64)
		value = (hours * 3600) + (min(minutes, 59) * 60) + min(seconds, 59) + (milliseconds / 1000)
	}
	return time.Duration(max(min(value, highest), max(0, lowest))) * time.Second
}
