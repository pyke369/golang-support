package mstore

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/jsonrpc"
	"golang.org/x/sys/unix"
)

const (
	ModeGauge      = 0x47415547
	ModeCounter    = 0x434f554e
	ModeText       = 0x54455854
	ModeBinary     = 0x44415441
	AggregateMin   = 1
	AggregateMax   = 2
	AggregateAvg   = 3
	AggregateFirst = 4
	AggregateLast  = 5
)

type Column struct {
	Mode        int
	Size        int
	Description string
	sync.Mutex
	mapping []map[int]*entry
}

const (
	magic       = 0x53544f52
	minInterval = 10
	maxInterval = 3600
	maxColumns  = 64
	maxSamples  = 1440
	metaSize    = 8 + maxColumns*38 + 128 + 4
)

var (
	modeNames = map[int]string{
		ModeGauge:   "gauge",
		ModeCounter: "counter",
		ModeText:    "text",
		ModeBinary:  "binary",
	}
	aggregateNames = map[int]string{
		AggregateMin:   "min",
		AggregateMax:   "max",
		AggregateAvg:   "avg",
		AggregateFirst: "first",
		AggregateLast:  "last",
	}
)

type metric struct {
	store       *Store
	name        string
	path        string
	description string
	interval    int
	size        int
	columns     []*Column
}
type chunk struct {
	last   time.Time
	handle *os.File
	data   []byte
}
type Store struct {
	prefix string
	sync.Mutex
	metrics map[string]*metric
	chunks  map[string]*chunk
	last    time.Time
}
type entry struct {
	index int
	value []byte
}

// store private api
func (s *Store) chunk(path string, size int, create bool) (data []byte, err error) {
	if size < 4 {
		return nil, errors.New("mstore: invalid size")
	}
	s.Lock()
	defer s.Unlock()
	if chunk, ok := s.chunks[path]; ok {
		if len(chunk.data) != size {
			return nil, errors.New("mstore: size mismatch")
		}
		chunk.last = time.Now()
		return chunk.data, nil
	}
	chunk, flags, created := &chunk{}, os.O_RDWR, false
	if create {
		flags |= os.O_CREATE
	}
	if _, err := os.Stat(path); err != nil {
		created = true
	}
	if chunk.handle, err = os.OpenFile(path, flags, 0644); err != nil {
		return nil, fmt.Errorf("mstore: %w", err)
	}
	if err = chunk.handle.Truncate(int64(size)); err != nil {
		chunk.handle.Close()
		return nil, fmt.Errorf("mstore: %w", err)
	}
	if chunk.data, err = unix.Mmap(int(uintptr(chunk.handle.Fd())), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
		chunk.handle.Close()
		return nil, fmt.Errorf("mstore: %w", err)
	}
	if created {
		binary.BigEndian.PutUint32(chunk.data[0:], magic)
		unix.Msync(chunk.data[0:4], unix.MS_SYNC)
	}
	if binary.BigEndian.Uint32(chunk.data[0:]) != magic {
		unix.Munmap(chunk.data)
		chunk.handle.Close()
		return nil, errors.New("mstore: invalid chunk")
	}
	chunk.last = time.Now()
	s.chunks[path] = chunk
	return chunk.data, nil
}
func (s *Store) cleanup() {
	s.Lock()
	defer s.Unlock()
	now := time.Now()
	if now.Sub(s.last) >= time.Minute {
		s.last = now
		for path, chunk := range s.chunks {
			if now.Sub(chunk.last) >= time.Minute {
				unix.Munmap(chunk.data)
				chunk.handle.Close()
				delete(s.chunks, path)
			}
		}
	}
}

// store public api
func NewStore(prefix string) (store *Store, err error) {
	os.MkdirAll(prefix, 0755)
	if info, err := os.Stat(prefix); err != nil || !info.IsDir() {
		return nil, errors.New("mstore: invalid store")
	}
	return &Store{prefix: prefix, metrics: map[string]*metric{}, chunks: map[string]*chunk{}}, nil
}
func (s *Store) Metric(name string) *metric {
	if name == "" {
		return nil
	}
	s.Lock()
	defer s.Unlock()
	if metric, ok := s.metrics[name]; ok {
		return metric
	}
	s.metrics[name] = &metric{store: s, name: name}
	return s.metrics[name]
}
func (s *Store) List(prefix string) (names []string) {
	names = []string{}
	filepath.WalkDir(filepath.Join(s.prefix, strings.ReplaceAll(prefix, ".", string(filepath.Separator))), func(path string, entry fs.DirEntry, err error) error {
		if entry != nil && entry.Name() == ".meta" {
			names = append(names, strings.ReplaceAll(strings.Trim(strings.TrimPrefix(filepath.Dir(path), s.prefix), string(filepath.Separator)), string(filepath.Separator), "."))
		}
		return nil
	})
	return
}
func (s *Store) Get(start, end time.Time, interval, aggregate int, names map[string][][]int) (result map[string]any) {
	result = map[string]any{}
	if count := len(names); count > 0 {
		queue := make(chan []any)
		for name, columns := range names {
			go func(name string, columns [][]int) {
				if value, err := s.Metric(name).Get(start, end, interval, columns); err == nil {
					queue <- []any{name, value}
				} else {
					queue <- []any{name, err.Error()}
				}
			}(name, columns)
		}
		for count > 0 {
			entry := <-queue
			result[entry[0].(string)] = entry[1]
			count--
		}
		close(queue)
	}
	return
}

// metric private api
func (m *metric) meta(create bool) error {
	if m.path == "" {
		m.path = filepath.Join(m.store.prefix, strings.ReplaceAll(m.name, ".", string(filepath.Separator)))
	}
	if m.size != 0 {
		return nil
	}
	path := filepath.Join(m.path, ".meta")
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != metaSize || binary.BigEndian.Uint32(data[0:]) != magic || crc32.ChecksumIEEE(data[:metaSize-4]) != binary.BigEndian.Uint32(data[metaSize-4:]) {
			return errors.New("mstore: invalid metadata")
		}
		m.interval = int(binary.BigEndian.Uint16(data[4:]))
		m.columns = []*Column{}
		m.size = 1
		if m.interval > 120 {
			m.size = 2
		}
		offset := 8
		for column := 0; column < int(binary.BigEndian.Uint16(data[6:])); column++ {
			m.columns = append(m.columns, &Column{
				Mode:        int(binary.BigEndian.Uint32(data[offset:])),
				Size:        int(binary.BigEndian.Uint16(data[offset+4:])),
				Description: string(bytes.Trim(data[offset+6:offset+38], "\x00")),
			})
			m.size += m.columns[column].Size
			offset += 38
		}
		m.description = string(bytes.Trim(data[metaSize-128-4:metaSize-4], "\x00"))
		return nil
	}
	if create {
		if len(m.columns) == 0 {
			return errors.New("mstore: empty columns list")
		}
		os.MkdirAll(m.path, 0755)
		if info, err := os.Stat(m.path); err != nil || !info.IsDir() {
			return errors.New("mstore: invalid metric")
		}
		m.interval = int(math.Round(float64(m.interval)/minInterval)) * minInterval
		m.interval = int(math.Max(minInterval, math.Min(float64(m.interval), maxInterval)))
		data := make([]byte, metaSize)
		binary.BigEndian.PutUint32(data[0:], magic)
		binary.BigEndian.PutUint16(data[4:], uint16(m.interval))
		binary.BigEndian.PutUint16(data[6:], uint16(len(m.columns)))
		m.size = 1
		if m.interval > 120 {
			m.size = 2
		}
		offset := 8
		for column := 0; column < maxColumns; column++ {
			if column < len(m.columns) {
				binary.BigEndian.PutUint32(data[offset:], uint32(m.columns[column].Mode))
				binary.BigEndian.PutUint16(data[offset+4:], uint16(m.columns[column].Size))
				copy(data[offset+6:offset+38], m.columns[column].Description)
				m.size += m.columns[column].Size
			}
			offset += 38
		}
		copy(data[metaSize-128-4:metaSize-4], m.description)
		binary.BigEndian.PutUint32(data[metaSize-4:], crc32.ChecksumIEEE(data[:metaSize-4]))
		if os.WriteFile(path, data, 0644) != nil {
			return errors.New("mstore: invalid metadata")
		}
		return nil
	}
	return errors.New("mstore: invalid metric")
}
func (m *metric) chunk(mtime time.Time, create bool) (data []byte, offset, delta int, err error) {
	mtime = mtime.UTC()
	start := time.Date(mtime.Year(), mtime.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(mtime.Year(), mtime.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	slots := int((mtime.Unix() - start.Unix()) / int64(m.interval))
	offset, delta = 4+slots*m.size, int(mtime.Unix()-(start.Unix()+int64(slots*int(m.interval))))
	data, err = m.store.chunk(filepath.Join(m.path, start.Format("2006-01")), 4+int(((end.Unix()-start.Unix())/int64(m.interval)))*m.size, create)
	return
}
func (m *metric) mapping(column int, flush bool) error {
	if column >= len(m.columns) || (m.columns[column].Mode != ModeText && m.columns[column].Mode != ModeBinary) {
		return errors.New("mstore: invalid column")
	}
	m.columns[column].Lock()
	defer m.columns[column].Unlock()
	path := filepath.Join(m.path, ".map"+strconv.FormatInt(int64(column), 10))
	if m.columns[column].mapping != nil {
		count := len(m.columns[column].mapping[1])
		if flush && count != 0 {
			size := 10
			for _, entry := range m.columns[column].mapping[1] {
				size += 2 + len(entry.value)
			}
			data, offset := make([]byte, size), 6
			binary.BigEndian.PutUint32(data[0:], magic)
			binary.BigEndian.PutUint16(data[4:], uint16(count))
			for index := 1; index <= count; index++ {
				length := len(m.columns[column].mapping[1][index].value)
				binary.BigEndian.PutUint16(data[offset:], uint16(length))
				copy(data[offset+2:offset+2+length], m.columns[column].mapping[1][index].value)
				offset += 2 + length
			}
			binary.BigEndian.PutUint32(data[size-4:], crc32.ChecksumIEEE(data[:size-4]))
			if os.WriteFile(path, data, 0644) != nil {
				return errors.New("mstore: invalid mapping")
			}
		}
		return nil
	}
	m.columns[column].mapping = []map[int]*entry{map[int]*entry{}, map[int]*entry{}}
	if data, err := os.ReadFile(path); err == nil {
		size, offset := len(data), 6
		if size < 10 || binary.BigEndian.Uint32(data[0:]) != magic || crc32.ChecksumIEEE(data[:size-4]) != binary.BigEndian.Uint32(data[size-4:]) {
			return errors.New("mstore: invalid mapping")
		}
		for index := 1; index <= int(binary.BigEndian.Uint16(data[4:])); index++ {
			length := int(binary.BigEndian.Uint16(data[offset:]))
			entry := &entry{index: index, value: make([]byte, length)}
			copy(entry.value, data[offset+2:offset+2+length])
			m.columns[column].mapping[0][int(crc32.ChecksumIEEE(entry.value))] = entry
			m.columns[column].mapping[1][index] = entry
			offset += 2 + length
		}
	}
	return nil
}
func (m *metric) put(value int64, size int, data []byte) {
	length := len(data)
	switch size {
	case 1:
		if length >= 1 {
			data[0] = byte(value)
		}
	case 2:
		if length >= 2 {
			binary.BigEndian.PutUint16(data[:], uint16(value))
		}
	case 4:
		if length >= 4 {
			binary.BigEndian.PutUint32(data[:], uint32(value))
		}
	case 8:
		if length >= 8 {
			binary.BigEndian.PutUint64(data[:], uint64(value))
		}
	}
}
func (m *metric) get(size int, data []byte) (value int64) {
	length := len(data)
	switch size {
	case 1:
		if length >= 1 {
			value = int64(data[0])
		}
	case 2:
		if length >= 2 {
			value = int64(binary.BigEndian.Uint16(data[:]))
		}
	case 4:
		if length >= 4 {
			value = int64(binary.BigEndian.Uint32(data[:]))
		}
	case 8:
		if length >= 8 {
			value = int64(binary.BigEndian.Uint64(data[:]))
		}
	}
	return
}

// metric public api
func (m *metric) WithDescription(description string) *metric {
	m.description = description
	return m
}
func (m *metric) WithInterval(interval int) *metric {
	m.interval = interval
	return m
}
func (m *metric) WithColumn(mode int, size int, description string) *metric {
	if mode == ModeGauge || mode == ModeCounter || mode == ModeText || mode == ModeBinary {
		if size == 0 {
			size = 2
			if mode == ModeText || mode == ModeBinary {
				size = 1
			}
		}
		if size == 1 || size == 2 || size == 4 || size == 8 {
			if m.columns == nil {
				m.columns = []*Column{}
			}
			if (mode == ModeText || mode == ModeBinary) && size > 2 {
				size = 2
			}
			if len(m.columns) < maxColumns {
				m.columns = append(m.columns, &Column{Mode: mode, Size: size, Description: description})
			}
		}
	}
	return m
}
func (m *metric) WithColumns(columns []*Column) *metric {
	for _, column := range columns {
		m.WithColumn(column.Mode, column.Size, column.Description)
	}
	return m
}

func (m *metric) Put(values ...any) error {
	return m.PutAt(time.Now(), values...)
}
func (m *metric) PutAt(mtime time.Time, values ...any) error {
	if time.Since(mtime) < 0 {
		return errors.New("mstore: metric time in future")
	}
	if err := m.meta(true); err != nil {
		return err
	}
	data, offset, delta, err := m.chunk(mtime, true)
	if err == nil {
		header, coffset := false, offset+1
		if m.interval > 120 {
			coffset++
		}
		for column, value := range values {
			if column < len(m.columns) {
				if value != nil {
					if !header {
						if m.interval > 120 {
							binary.BigEndian.PutUint16(data[offset:], uint16(0x8000+(delta&0x7fff)))
						} else {
							data[offset] = byte(0x80 + (delta & 0x7f))
						}
						header = true
					}
					switch m.columns[column].Mode {
					case ModeGauge, ModeCounter:
						m.put(int64(jsonrpc.Number(value)), m.columns[column].Size, data[coffset:])

					case ModeText, ModeBinary:
						var content []byte

						if m.columns[column].Mode == ModeText {
							if value, ok := value.(string); ok {
								content = []byte(value)
							}
						} else if value, ok := value.([]byte); ok {
							content = value
						}
						if len(content) > 0 && m.mapping(column, false) == nil {
							key := int(crc32.ChecksumIEEE(content))
							m.columns[column].Lock()
							if value, ok := m.columns[column].mapping[0][key]; ok {
								m.columns[column].Unlock()
								m.put(int64(value.index), m.columns[column].Size, data[coffset:])

							} else if len(m.columns[column].mapping[0]) < (1<<(m.columns[column].Size*8))-2 {
								value := &entry{index: len(m.columns[column].mapping[0]) + 1, value: content}
								m.columns[column].mapping[0][key] = value
								m.columns[column].mapping[1][value.index] = value
								m.columns[column].Unlock()
								if m.mapping(column, true) == nil {
									m.put(int64(value.index), m.columns[column].Size, data[coffset:])
								}
							} else {
								m.columns[column].Unlock()
							}
						}
					}
				}
				coffset += m.columns[column].Size
			}
		}
	}
	m.store.cleanup()
	return err
}
func (m *metric) Get(start, end time.Time, interval int, columns [][]int) (result map[string]any, err error) {
	if err := m.meta(false); err != nil {
		return nil, err
	}
	result = map[string]any{"range": []int64{0, 0}, "columns": [][]any{}, "values": []any{}}
	mapping, duplicates := [][]int{}, map[int]bool{}
	for _, column := range columns {
		if len(column) > 0 && column[0] < len(m.columns) {
			aggregate := 0
			if len(column) > 1 {
				aggregate = column[1]
			}
			if aggregate <= 0 || aggregate > AggregateLast {
				aggregate = AggregateAvg
			}
			if _, ok := duplicates[(column[0]<<8)+aggregate]; !ok {
				duplicates[(column[0]<<8)+aggregate] = true
				result["columns"] = append(result["columns"].([][]any), []any{column[0], modeNames[m.columns[column[0]].Mode], aggregateNames[aggregate], m.columns[column[0]].Description})
				offset := 1
				if m.interval > 120 {
					offset++
				}
				for index := 0; index < column[0]; index++ {
					offset += m.columns[index].Size
				}
				mapping = append(mapping, []int{column[0], m.columns[column[0]].Mode, m.columns[column[0]].Size, offset, aggregate})
			}
		}
	}
	if len(result["columns"].([][]any)) == 0 {
		return nil, errors.New("mstore: empty columns list")
	}
	if end.IsZero() || end.After(time.Now()) {
		end = time.Now()
	}
	if start.IsZero() {
		start = end.Add(-time.Hour)
	}
	start = start.UTC().Add(-time.Duration(start.Unix()%int64(m.interval)) * time.Second).Round(time.Duration(m.interval) * time.Second)
	end = end.UTC().Add(-time.Duration(end.Unix()%int64(m.interval)) * time.Second).Round(time.Duration(m.interval) * time.Second)
	if end.Sub(start) >= time.Duration(m.interval)*time.Second {
		interval = int(math.Round(float64(interval)/float64(m.interval))) * m.interval
		interval = int(math.Max(float64(interval), float64(m.interval)))
		seconds := int(end.Unix() - start.Unix())
		if seconds/interval > maxSamples {
			interval = int(math.Ceil((float64(seconds)/float64(maxSamples))/float64(m.interval)) * float64(m.interval))
		}
		result["range"].([]int64)[0], result["range"].([]int64)[1] = start.Unix(), int64(interval)

		var data []byte
		current, values, steps, msteps, step, offset := start, []any{}, interval/m.interval, make([]int, len(mapping)), 0, 0
		for current.Before(end) {
			if data == nil {
				data, offset, _, _ = m.chunk(current, false)
			}
			if data != nil {
				if data[offset]&0x80 != 0 {
					if len(values) == 0 {
						for _, item := range mapping {
							switch item[1] {
							case ModeGauge, ModeCounter:
								values = append(values, int64(-1))
							case ModeText, ModeBinary:
								values = append(values, []byte{})
							}
						}
					}
					for index, item := range mapping {
						switch item[1] {
						case ModeGauge:
							msteps[index]++
							value := m.get(item[2], data[offset+item[3]:])
							switch item[4] {
							case AggregateMin:
								if values[index].(int64) < 0 || value < values[index].(int64) {
									values[index] = value
								}
							case AggregateMax:
								if value > values[index].(int64) {
									values[index] = value
								}
							case AggregateAvg:
								if values[index].(int64) < 0 {
									values[index] = value
								} else {
									values[index] = values[index].(int64) + value
								}
							case AggregateFirst:
								if values[index].(int64) < 0 {
									values[index] = value
								}
							case AggregateLast:
								values[index] = value
							}

						case ModeCounter:
							value, delta, pvalue, pdelta := m.get(item[2], data[offset+item[3]:]), 0, int64(-1), 0
							if m.interval > 120 {
								delta = int(binary.BigEndian.Uint16(data[offset:]) & 0x7fff)
							} else {
								delta = int(data[offset] & 0x7f)
							}
							if offset-m.size >= 4 && data[offset-m.size]&0x80 != 0 {
								pvalue = m.get(item[2], data[offset-m.size+item[3]:])
								if m.interval > 120 {
									pdelta = int(binary.BigEndian.Uint16(data[offset-m.size:]) & 0x7fff)
								} else {
									pdelta = int(data[offset-m.size] & 0x7f)
								}
							}
							if pvalue >= 0 {
								value = (value - pvalue) / int64(m.interval+delta-pdelta)
								msteps[index]++
								switch item[4] {
								case AggregateMin:
									if values[index].(int64) < 0 || value < values[index].(int64) {
										values[index] = value
									}
								case AggregateMax:
									if value > values[index].(int64) {
										values[index] = value
									}
								case AggregateAvg:
									if values[index].(int64) < 0 {
										values[index] = value
									} else {
										values[index] = values[index].(int64) + value
									}
								case AggregateFirst:
									if values[index].(int64) < 0 {
										values[index] = value
									}
								case AggregateLast:
									values[index] = value
								}
							}

						case ModeText, ModeBinary:
							if value := m.get(item[2], data[offset+item[3]:]); value != 0 {
								if m.mapping(item[0], false) == nil {
									if entry, ok := m.columns[item[0]].mapping[1][int(value)]; ok {
										length := len(values[index].([]byte))
										switch item[4] {
										case AggregateMin:
											if length == 0 || len(entry.value) < length {
												values[index] = entry.value
											}
										case AggregateMax:
											if len(entry.value) > length {
												values[index] = entry.value
											}
										case AggregateFirst:
											if length == 0 {
												values[index] = entry.value
											}
										case AggregateLast:
											values[index] = entry.value
										}
									}
								}
							}
						}
					}
				}
				offset += m.size
				if offset >= len(data) {
					data = nil
				}
			}

			step++
			current = current.Add(time.Duration(m.interval) * time.Second)
			if step >= steps || !current.Before(end) {
				if len(values) == len(mapping) {
					for index, item := range mapping {
						if item[4] == AggregateAvg && (item[1] == ModeGauge || item[1] == ModeCounter) && msteps[index] > 0 {
							values[index] = values[index].(int64) / int64(msteps[index])
						}
						if item[1] == ModeText {
							values[index] = string(values[index].([]byte))
						} else if item[1] == ModeBinary {
							values[index] = base64.StdEncoding.EncodeToString(values[index].([]byte))
						}
					}
				}
				result["values"] = append(result["values"].([]any), values)
				values, msteps, step = []any{}, make([]int, len(mapping)), 0
			}
		}
	}
	m.store.cleanup()
	return
}
