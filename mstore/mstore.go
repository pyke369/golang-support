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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
	"golang.org/x/sys/unix"
)

const (
	ModeGauge   = 0x47415547
	ModeCounter = 0x434f554e
	ModeText    = 0x54455854
	ModeBinary  = 0x44415441

	AggregateMinimum    = 1
	AggregateMaximum    = 2
	AggregateAverage    = 3
	AggregateFirst      = 4
	AggregateLast       = 5
	AggregateHistogram  = 6
	AggregatePercentile = 7
	AggregateRaw        = 8

	magic       = 0x53544f52
	minInterval = 10
	maxInterval = 3600
	maxColumns  = 64
	maxSamples  = 1440
	metaSize    = 8 + maxColumns*38 + 128 + 4
)

type Store struct {
	prefix string
	sync.Mutex
	metrics map[string]*metric
	chunks  map[string]*chunk
	last    time.Time
}
type Column struct {
	Mode        int64
	Size        int64
	Description string
	sync.Mutex
	mapping []map[int]*entry
}
type metric struct {
	store       *Store
	name        string
	path        string
	description string
	interval    int64
	size        int64
	columns     []*Column
	frozen      bool
	sync.Mutex
}
type chunk struct {
	last   time.Time
	handle *os.File
	data   []byte
}
type entry struct {
	index int
	value []byte
}

var (
	ModeNames = map[int64]string{
		ModeGauge:   "gauge",
		ModeCounter: "counter",
		ModeText:    "text",
		ModeBinary:  "binary",
	}
	ModeIndexes = map[string]int64{
		"gauge":   ModeGauge,
		"counter": ModeCounter,
		"text":    ModeText,
		"binary":  ModeBinary,
	}
	AggregateNames = map[int64]string{
		AggregateMinimum:    "minimum",
		AggregateMaximum:    "maximum",
		AggregateAverage:    "average",
		AggregateFirst:      "first",
		AggregateLast:       "last",
		AggregateHistogram:  "histogram",
		AggregatePercentile: "percentile",
		AggregateRaw:        "raw",
	}
	AggregateIndexes = map[string]int64{
		"min":        AggregateMinimum,
		"minimum":    AggregateMinimum,
		"max":        AggregateMaximum,
		"maximum":    AggregateMaximum,
		"avg":        AggregateAverage,
		"average":    AggregateAverage,
		"first":      AggregateFirst,
		"last":       AggregateLast,
		"histo":      AggregateHistogram,
		"histogram":  AggregateHistogram,
		"percent":    AggregatePercentile,
		"percentile": AggregatePercentile,
		"raw":        AggregateRaw,
	}
)

// store private api
func (s *Store) chunk(path string, size int64, create bool) (data []byte, err error) {
	if size < 4 {
		return nil, errors.New("mstore: invalid size")
	}
	s.Lock()
	defer s.Unlock()
	if chunk, ok := s.chunks[path]; ok {
		if len(chunk.data) != int(size) {
			return nil, errors.New("mstore: size mismatch")
		}
		chunk.last = time.Now()
		if !create || chunk.handle != nil {
			return chunk.data, nil
		}
	}
	chunk, flags, created := &chunk{}, os.O_RDWR, false
	if create {
		flags |= os.O_CREATE
	}
	if _, err := os.Stat(path); err != nil {
		if !create {
			if info, err := os.Stat(filepath.Dir(path)); err == nil && info.IsDir() {
				chunk.last, chunk.data = time.Now(), make([]byte, size)
				s.chunks[path] = chunk
				return chunk.data, nil
			}
		}
		created = true
	}
	if chunk.handle, err = os.OpenFile(path, flags, 0644); err != nil {
		return nil, fmt.Errorf("mstore: %w", err)
	}
	if err = chunk.handle.Truncate(size); err != nil {
		chunk.handle.Close()
		return nil, fmt.Errorf("mstore: %w", err)
	}
	if chunk.data, err = unix.Mmap(int(uintptr(chunk.handle.Fd())), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
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
				if chunk.handle != nil {
					unix.Munmap(chunk.data)
					chunk.handle.Close()
				}
				delete(s.chunks, path)
			}
		}
	}
}

// store public api
func NewStore(prefix string, readonly ...bool) (store *Store, err error) {
	if len(readonly) == 0 || !readonly[0] {
		os.MkdirAll(prefix, 0755)
	}
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
func (s *Store) Get(start, end time.Time, interval int64, names map[string][][]int64) (result map[string]any) {
	result = map[string]any{}
	if count := len(names); count > 0 {
		queue := make(chan []any)
		for name, columns := range names {
			go func(name string, columns [][]int64) {
				if value, err := s.Metric(name).Get(start, end, interval, columns); err == nil {
					queue <- []any{name, value}
				} else {
					queue <- []any{name, map[string]string{"error": err.Error()}}
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
		m.interval, m.columns, m.size = int64(binary.BigEndian.Uint16(data[4:])), []*Column{}, 1
		if m.interval > 120 {
			m.size = 2
		}
		offset := 8
		for column := 0; column < int(binary.BigEndian.Uint16(data[6:])); column++ {
			m.columns = append(m.columns, &Column{
				Mode:        int64(binary.BigEndian.Uint32(data[offset:])),
				Size:        int64(binary.BigEndian.Uint16(data[offset+4:])),
				Description: string(bytes.Trim(data[offset+6:offset+38], "\x00")),
			})
			m.size += m.columns[column].Size
			offset += 38
		}
		m.description, m.frozen = string(bytes.Trim(data[metaSize-128-4:metaSize-4], "\x00")), true
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
		m.interval = int64(math.Round(float64(m.interval)/minInterval)) * minInterval
		m.interval = int64(math.Max(minInterval, math.Min(float64(m.interval), maxInterval)))
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
		m.frozen = true
		return nil
	}
	return errors.New("mstore: invalid metric")
}

func (m *metric) chunk(atime time.Time, create bool) (data []byte, offset, delta int64, err error) {
	atime = atime.UTC()
	start := time.Date(atime.Year(), atime.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(atime.Year(), atime.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	slots := (atime.Unix() - start.Unix()) / m.interval
	offset, delta = 4+slots*m.size, atime.Unix()-start.Unix()-(slots*m.interval)
	data, err = m.store.chunk(filepath.Join(m.path, start.Format("2006-01")), 4+((end.Unix()-start.Unix())/m.interval)*m.size, create)
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
func (m *metric) put(value int64, size int64, data []byte) {
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
func (m *metric) get(size int64, data []byte) (value int64) {
	length := len(data)
	switch size {
	case 1:
		if length >= 1 {
			value = int64(int8(data[0]))
		}
	case 2:
		if length >= 2 {
			value = int64(int16(binary.BigEndian.Uint16(data[:])))
		}
	case 4:
		if length >= 4 {
			value = int64(int32(binary.BigEndian.Uint32(data[:])))
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
	if !m.frozen {
		m.description = description
	}
	return m
}
func (m *metric) WithInterval(interval int64) *metric {
	if !m.frozen {
		m.interval = interval
	}
	return m
}
func (m *metric) WithColumn(mode int64, size int64, description string) *metric {
	if !m.frozen {
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
	}
	return m
}
func (m *metric) WithColumns(columns []*Column) *metric {
	for _, column := range columns {
		m.WithColumn(column.Mode, column.Size, column.Description)
	}
	return m
}

func (m *metric) Metadata() (metadata map[string]any, err error) {
	if err := m.meta(false); err != nil {
		return nil, err
	}
	columns, names, first, last := []map[string]any{}, []string{}, int64(-1), int64(-1)
	for _, column := range m.columns {
		columns = append(columns, map[string]any{
			"mode":        ModeNames[column.Mode],
			"size":        column.Size,
			"description": column.Description,
		})
	}
	if len(columns) != 0 {
		filepath.WalkDir(m.path, func(path string, entry fs.DirEntry, err error) error {
			if entry != nil && entry.Type().IsRegular() && rcache.Get(`^\d{4}-\d{2}$`).MatchString(entry.Name()) {
				names = append(names, entry.Name())
			}
			return nil
		})
		sort.Strings(names)
		if len(names) != 0 {
			if captures := rcache.Get(`^(\d{4})-(\d{2})$`).FindStringSubmatch(names[0]); captures != nil {
				year, _ := strconv.Atoi(captures[1])
				month, _ := strconv.Atoi(captures[2])
				if year != 0 && month != 0 {
					start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
					for start.Year() == year && int(start.Month()) == month && first < 0 {
						if result, err := m.Get(start, start.Add(time.Duration(m.interval*maxSamples)*time.Second), m.interval, [][]int64{[]int64{0, AggregateLast}}); err == nil {
							if rrange := j.Slice(result["range"]); len(rrange) >= 2 {
								for index, value := range j.Slice(result["values"]) {
									if len(j.Slice(value)) != 0 {
										first = int64(j.Number(j.SliceItem(rrange, 0))) + (int64(index) * int64(j.Number(j.SliceItem(rrange, 1))))
										break
									}
								}
							}
						}
						start = start.Add(time.Duration(m.interval*maxSamples) * time.Second)
					}
				}
			}
			if captures := rcache.Get(`^(\d{4})-(\d{2})$`).FindStringSubmatch(names[len(names)-1]); captures != nil {
				year, _ := strconv.Atoi(captures[1])
				month, _ := strconv.Atoi(captures[2])
				if year != 0 && month != 0 {
					start := time.Date(year, time.Month(month)+1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Duration(m.interval*maxSamples) * time.Second)
					for start.Year() == year && int(start.Month()) == month && last < 0 {
						if result, err := m.Get(start, start.Add(time.Duration(m.interval*maxSamples)*time.Second), m.interval, [][]int64{[]int64{0, AggregateLast}}); err == nil {
							if rrange := j.Slice(result["range"]); len(rrange) >= 2 {
								values := j.Slice(result["values"])
								for index := len(values) - 1; index >= 0; index-- {
									if len(j.Slice(values[index])) != 0 {
										last = int64(j.Number(j.SliceItem(rrange, 0))) + (int64(index) * int64(j.Number(j.SliceItem(rrange, 1))))
										break
									}
								}
							}
						}
						start = start.Add(-time.Duration(m.interval*maxSamples) * time.Second)
					}
				}
			}
		}
	}
	return map[string]any{
		"store":       m.store.prefix,
		"name":        m.name,
		"description": m.description,
		"interval":    m.interval,
		"columns":     columns,
		"first":       first,
		"last":        last,
	}, nil
}

func (m *metric) Export() (export map[string]any, err error) {
	metadata, err := m.Metadata()
	if err != nil {
		return nil, err
	}
	last := int64(j.Number(metadata["last"]))
	start, end := time.Unix(int64(j.Number(metadata["first"])), 0), time.Unix(last, 0)
	length, columns, values := len(j.Slice(metadata["columns"])), [][]int64{}, [][]any{}
	if length != 0 {
		for index := 0; index < length; index++ {
			columns = append(columns, []int64{int64(index), AggregateRaw})
		}
		for !start.After(end) {
			lend := start.Add(time.Duration(m.interval*maxSamples) * time.Second)
			if lend.After(end) {
				lend = end.Add(time.Duration(m.interval) * time.Second)
			}
			if result, err := m.Get(start, lend, m.interval, columns, true); err == nil {
				if rrange := j.Slice(result["range"]); len(rrange) >= 2 {
					at, step := int64(j.Number(j.SliceItem(rrange, 0))), int64(j.Number(j.SliceItem(rrange, 1)))
					for index, value := range j.Slice(result["values"]) {
						entry := j.Slice(value)
						if at+(int64(index)*step) <= last && len(entry) == len(columns)+1 {
							values = append(values, entry)
						}
					}
				}
			}
			start = start.Add(time.Duration(m.interval*maxSamples) * time.Second)
		}
	}
	return map[string]any{"metadata": metadata, "values": values}, nil
}
func (m *metric) Import(input map[string]any) error {
	if input == nil {
		return errors.New("mstore: invalid parameter")
	}
	metadata := j.Map(input["metadata"])
	if value := int64(j.Number(metadata["interval"])); value != 0 {
		m = m.WithInterval(value)
	}
	if value := j.String(metadata["description"]); value != "" {
		m = m.WithDescription(value)
	}
	columns := j.Slice(metadata["columns"])
	if len(columns) == 0 {
		return errors.New("mstore: empty columns list")
	}
	for _, value := range columns {
		column := j.Map(value)
		if mode := ModeIndexes[j.String(column["mode"])]; mode != 0 {
			m = m.WithColumn(mode, int64(j.Number(column["size"])), j.String(column["description"]))
		} else {
			return fmt.Errorf(`mstore: invalid column mode "%s"`, j.String(column["mode"]))
		}
	}
	for _, value := range j.Slice(input["values"]) {
		if entry := j.Slice(value); len(entry) == len(columns)+1 {
			if at, err := time.Parse(time.DateTime, j.String(entry[0])); err == nil {
				if err := m.PutAt(at, entry[1:]...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *metric) Put(values ...any) error {
	return m.PutAt(time.Now(), values...)
}
func (m *metric) PutAt(atime time.Time, values ...any) error {
	m.Lock()
	defer m.Unlock()
	if time.Since(atime) < 0 {
		return errors.New("mstore: metric time in future")
	}
	if err := m.meta(true); err != nil {
		return err
	}
	data, offset, delta, err := m.chunk(atime, true)
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
						m.put(int64(j.Number(value)), m.columns[column].Size, data[coffset:])

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
func (m *metric) Get(start, end time.Time, interval int64, columns [][]int64, prepend ...bool) (result map[string]any, err error) {
	m.Lock()
	defer m.Unlock()
	if err := m.meta(false); err != nil {
		return nil, err
	}
	result = map[string]any{"range": []int64{0, 0}, "columns": [][]any{}, "values": []any{}}
	mapping, duplicates := [][]int64{}, map[int64]bool{}
	for _, column := range columns {
		if len(column) > 0 && int(column[0]) < len(m.columns) {
			aggregate, min, max := int64(0), int64(math.MinInt64), int64(math.MaxInt64)
			if len(column) > 1 {
				aggregate = column[1]
			}
			if aggregate <= 0 || aggregate > AggregateRaw {
				aggregate = AggregateAverage
			}
			if len(column) > 2 {
				min = column[2]
			}
			if len(column) > 3 {
				max = column[3]
			}
			if _, ok := duplicates[(column[0]<<8)+aggregate]; !ok {
				duplicates[(column[0]<<8)+aggregate] = true
				result["columns"] = append(result["columns"].([][]any), []any{column[0], ModeNames[m.columns[column[0]].Mode], AggregateNames[aggregate], m.columns[column[0]].Description})
				offset := int64(1)
				if m.interval > 120 {
					offset++
				}
				for index := 0; index < int(column[0]); index++ {
					offset += m.columns[index].Size
				}
				mapping = append(mapping, []int64{column[0], m.columns[column[0]].Mode, m.columns[column[0]].Size, offset, aggregate, min, max})
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
		interval = int64(math.Round(float64(interval)/float64(m.interval))) * m.interval
		interval = int64(math.Max(float64(interval), float64(m.interval)))
		seconds := end.Unix() - start.Unix()
		if seconds/interval > maxSamples {
			interval = int64(math.Ceil((float64(seconds)/float64(maxSamples))/float64(m.interval)) * float64(m.interval))
		}
		result["range"].([]int64)[0], result["range"].([]int64)[1] = start.Unix(), int64(interval)

		var data []byte
		current, values, steps, msteps, step, offset, ptime := start, []any{}, interval/m.interval, make([]int, len(mapping)), int64(0), int64(0), int64(0)
		for current.Before(end) {
			if data == nil {
				data, offset, _, _ = m.chunk(current, false)
			}
			if data != nil {
				if step == 0 {
					ptime = current.Unix()
				}
				if data[offset]&0x80 != 0 {
					if step == 0 {
						if m.interval > 120 {
							ptime += int64(binary.BigEndian.Uint16(data[offset:]) & 0x7fff)
						} else {
							ptime += int64(data[offset] & 0x7f)
						}
					}
					if len(values) == 0 {
						for _, item := range mapping {
							if item[4] == AggregateHistogram || item[4] == AggregatePercentile {
								values = append(values, map[string]int{})
							} else {
								switch item[1] {
								case ModeGauge, ModeCounter:
									values = append(values, int64(math.MinInt64))
								case ModeText, ModeBinary:
									values = append(values, []byte{})
								}
							}
						}
					}
					for index, item := range mapping {
						switch item[1] {
						case ModeGauge:
							msteps[index]++
							value := m.get(item[2], data[offset+item[3]:])
							if item[4] == AggregateHistogram || item[4] == AggregatePercentile {
								if item[5] > 0 {
									value /= item[5]
								}
								values[index].(map[string]int)[strconv.FormatInt(value, 10)]++
							} else if value >= item[5] && value <= item[6] {
								switch item[4] {
								case AggregateMinimum:
									if values[index].(int64) == math.MinInt64 || value < values[index].(int64) {
										values[index] = value
									}
								case AggregateMaximum:
									if value > values[index].(int64) {
										values[index] = value
									}
								case AggregateAverage:
									if values[index].(int64) == math.MinInt64 {
										values[index] = value
									} else {
										values[index] = values[index].(int64) + value
									}
								case AggregateFirst:
									if values[index].(int64) == math.MinInt64 {
										values[index] = value
									}
								case AggregateLast, AggregateRaw:
									values[index] = value
								}
							}

						case ModeCounter:
							value := m.get(item[2], data[offset+item[3]:])
							if item[4] == AggregateRaw {
								values[index] = value
							} else {
								delta, pvalue, pdelta := int64(0), int64(-1), int64(0)
								if m.interval > 120 {
									delta = int64(binary.BigEndian.Uint16(data[offset:]) & 0x7fff)
								} else {
									delta = int64(data[offset] & 0x7f)
								}
								if offset-m.size >= 4 && data[offset-m.size]&0x80 != 0 {
									pvalue = m.get(item[2], data[offset-m.size+item[3]:])
									if m.interval > 120 {
										pdelta = int64(binary.BigEndian.Uint16(data[offset-m.size:]) & 0x7fff)
									} else {
										pdelta = int64(data[offset-m.size] & 0x7f)
									}
								}
								if pvalue >= 0 {
									msteps[index]++
									value = (value - pvalue) / int64(m.interval+delta-pdelta)
								} else {
									value = 0
								}
								if item[4] == AggregateHistogram || item[4] == AggregatePercentile {
									if item[5] > 0 {
										value /= item[5]
									}
									values[index].(map[string]int)[strconv.FormatInt(value, 10)]++
								} else if value >= item[5] && value <= item[6] {
									switch item[4] {
									case AggregateMinimum:
										if values[index].(int64) == math.MinInt64 || value < values[index].(int64) {
											values[index] = value
										}
									case AggregateMaximum:
										if value > values[index].(int64) {
											values[index] = value
										}
									case AggregateAverage:
										if values[index].(int64) == math.MinInt64 {
											values[index] = value
										} else {
											values[index] = values[index].(int64) + value
										}
									case AggregateFirst:
										if values[index].(int64) == math.MinInt64 {
											values[index] = value
										}
									case AggregateLast:
										values[index] = value
									}
								}
							}

						case ModeText, ModeBinary:
							if value := m.get(item[2], data[offset+item[3]:]); value != 0 {
								if m.mapping(int(item[0]), false) == nil {
									if entry, ok := m.columns[item[0]].mapping[1][int(value)]; ok {
										if item[4] == AggregateHistogram || item[4] == AggregatePercentile {
											value := string(entry.value)
											if item[1] == ModeBinary {
												value = base64.StdEncoding.EncodeToString(entry.value)
											}
											values[index].(map[string]int)[value]++
										} else {
											length := len(values[index].([]byte))
											switch item[4] {
											case AggregateMinimum:
												if length == 0 || len(entry.value) < length {
													values[index] = entry.value
												}
											case AggregateMaximum:
												if len(entry.value) > length {
													values[index] = entry.value
												}
											case AggregateFirst:
												if length == 0 {
													values[index] = entry.value
												}
											case AggregateAverage, AggregateLast, AggregateRaw:
												values[index] = entry.value
											}
										}
									}
								}
							}
						}
					}
				}
				offset += m.size
				if int(offset) >= len(data) {
					data = nil
				}
			}

			step++
			current = current.Add(time.Duration(m.interval) * time.Second)
			if step >= steps || !current.Before(end) {
				if len(values) == len(mapping) {
					for index, item := range mapping {
						if item[4] == AggregateAverage && (item[1] == ModeGauge || item[1] == ModeCounter) && msteps[index] > 0 {
							if values[index].(int64) == math.MinInt64 {
								values[index] = int64(0)
							} else {
								values[index] = values[index].(int64) / int64(msteps[index])
							}
						}
						if item[4] == AggregatePercentile {
							if item[1] == ModeGauge || item[1] == ModeCounter {
								list, total := make([][2]int64, 0, len(values[index].(map[string]int))), 0
								for key, count := range values[index].(map[string]int) {
									if value, err := strconv.ParseInt(key, 10, 64); err == nil {
										list = append(list, [2]int64{value, int64(count)})
										total += count
									}
								}
								values[index] = 0
								if total != 0 {
									sort.Slice(list, func(a, b int) bool { return list[a][0] < list[b][0] })
									if item[6] == int64(math.MaxInt64) {
										item[6] = 95
									}
									item[6] = int64(math.Min(100, math.Max(0, float64(item[6]))))
									if item[6] == 0 {
										values[index] = list[0][0]
									} else if item[6] == 100 {
										values[index] = list[len(list)-1][0]
									} else {
										percentile := 0.0
										for _, value := range list {
											ok1 := float64(item[6]) >= percentile
											percentile += float64(value[1]) * 100 / float64(total)
											ok2 := float64(item[6]) < percentile
											if ok1 && ok2 {
												values[index] = value[0]
												break
											}
										}
									}
								}
							}

						} else if item[4] != AggregateHistogram {
							if item[1] == ModeText {
								values[index] = string(values[index].([]byte))
							} else if item[1] == ModeBinary {
								values[index] = base64.StdEncoding.EncodeToString(values[index].([]byte))
							}
						}
					}
				}
				if len(prepend) != 0 && prepend[0] {
					result["values"] = append(result["values"].([]any), append([]any{ptime}, values...))
				} else {
					result["values"] = append(result["values"].([]any), values)
				}
				values, msteps, step = []any{}, make([]int, len(mapping)), 0
			}
		}
	}
	m.store.cleanup()
	return
}
