package ustr

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

var (
	bools = [][2]string{
		[2]string{"false", "true"},
		[2]string{"no", "yes"},
		[2]string{"off", "on"},
		[2]string{"failure", "success"},
		[2]string{"0", "1"},
	}
	htable = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	days   = [][]byte{
		nil,
		[]byte("Monday"),
		[]byte("Tuesday"),
		[]byte("Wednesday"),
		[]byte("Thursday"),
		[]byte("Friday"),
		[]byte("Saturday"),
		[]byte("Sunday"),
	}
	months = [][]byte{
		nil,
		[]byte("January"),
		[]byte("February"),
		[]byte("March"),
		[]byte("April"),
		[]byte("May"),
		[]byte("June"),
		[]byte("July"),
		[]byte("August"),
		[]byte("September"),
		[]byte("October"),
		[]byte("November"),
		[]byte("December"),
	}
)

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	if !strings.HasPrefix(err.Error(), msg+": ") {
		return fmt.Errorf("%s: %w", msg, err)
	}

	return err
}

func Bool(in bool, extra ...int) (out string) {
	mode := 0
	if len(extra) != 0 {
		mode = min(len(bools)-1, max(0, extra[0]))
	}
	if in {
		return bools[mode][1]
	}

	return bools[mode][0]
}

func Int(in int, extra ...int) string {
	value, size, pad, tsep := strconv.Itoa(in), 0, byte(' '), ""
	if len(extra) > 0 {
		size = extra[0]
		if len(extra) > 1 && size >= 0 {
			if extra[1] >= 0x20 && extra[1] < 0x7f {
				pad = byte(extra[1])

			} else {
				pad = '0'
			}
		}
		if len(extra) > 2 {
			pad = byte(' ')
			if extra[2] >= 0x20 && extra[2] < 0x7f {
				tsep = string(byte(extra[2]))

			} else {
				tsep = ","
			}
		}
	}

	if tsep != "" {
		separated := ""
		for index, c := range Reverse(value) {
			if index != 0 && index%3 == 0 && c != '-' {
				separated = tsep + separated
			}
			separated = string(c) + separated
		}
		value = separated
	}

	usize := size
	if size < 0 {
		if usize == math.MinInt {
			return value
		}
		usize = -usize
	}
	usize = min(1<<16, usize)
	length := len(value)
	if length >= usize {
		return value
	}

	out := make([]byte, usize)
	if size > 0 {
		if in >= 0 || pad == ' ' {
			for index := 0; index < usize-length; index++ {
				out[index] = pad
			}
			copy(out[usize-length:], value)

		} else {
			out[0] = '-'
			for index := 1; index <= usize-length; index++ {
				out[index] = '0'
			}
			copy(out[usize-length+1:], value[1:])
		}

	} else {
		copy(out, value)
		for index := length; index < usize; index++ {
			out[index] = pad
		}
	}

	return string(out)
}

func Float(in float64, extra ...int) string {
	precision := 0
	if len(extra) > 0 {
		precision = extra[0]
	}
	if len(extra) > 1 {
		return String(strconv.FormatFloat(in, 'f', precision, 64), extra[1:]...)
	}

	return strconv.FormatFloat(in, 'f', precision, 64)
}

func String(in string, extra ...int) string {
	length, pad := len(in), byte(' ')
	size := length
	if len(extra) > 0 {
		size = extra[0]
		if len(extra) > 1 {
			if value := byte(extra[1]); value >= ' ' && value <= '~' {
				pad = value
			}
		}
	}
	if size == 0 {
		return ""
	}

	usize := size
	if size < 0 {
		if usize == math.MinInt {
			return in
		}
		usize = -usize
	}
	usize = min(1<<16, usize)
	if usize == len(in) {
		return in
	}

	out := make([]byte, usize)
	if usize < length {
		copy(out, in)

	} else {
		if size < 0 {
			copy(out, in)
			for index := length; index < usize; index++ {
				out[index] = pad
			}

		} else {
			for index := 0; index < usize-length; index++ {
				out[index] = pad
			}
			copy(out[usize-length:], in)
		}
	}

	return string(out)
}

func Truncate(in string, length int, ellipsis ...bool) (out string) {
	if in = strings.TrimSpace(in); in == "" || length <= 0 {
		return
	}

	end, count := len(in), 0
	for i := range in {
		if count == length {
			end = i
			break
		}
		count++
	}
	out = strings.TrimSpace(in[:end])

	if end < len(in) && len(ellipsis) != 0 && ellipsis[0] {
		out += "..."
	}

	return
}

func Strip(in, charset string) string {
	for _, strip := range charset {
		if strings.ContainsRune(in, strip) {
			in = strings.ReplaceAll(in, string(strip), "")
		}
	}

	return in
}

func Replace(in string, pairs [][2]string) string {
	for _, pair := range pairs {
		if strings.HasPrefix(pair[0], "~") {
			if matcher, err := rcache.Get(strings.TrimSpace(strings.TrimPrefix(pair[0], "~"))); err == nil {
				in = matcher.ReplaceAllString(in, pair[1])
			}

		} else {
			in = strings.ReplaceAll(in, pair[0], pair[1])
		}
	}

	return in
}

func Hex(in []byte, extra ...byte) string {
	length, pad := len(in), byte(0)
	if length == 0 {
		return ""
	}
	if len(extra) != 0 {
		pad = extra[0]
	}
	size := length * 2
	if pad != 0 {
		size += length - 1
	}
	out, offset := make([]byte, size), 0
	for index := 0; index < length; index++ {
		out[offset], out[offset+1] = htable[in[index]>>4], htable[in[index]&0x0f]
		offset += 2
		if pad != 0 && index < length-1 {
			out[offset] = pad
			offset++
		}
	}

	return string(out)
}

func HexInt(in uint64, size int) string {
	size = min(8, max(1, size))
	value := [8]byte{}
	binary.BigEndian.PutUint64(value[:], in)

	return Hex(value[8-size:])
}

func IPv4(in uint32) string {
	ip := net.IPv4(0, 0, 0, 0).To4()
	binary.BigEndian.PutUint32(ip, in)

	return ip.String()
}

func Binary(dst []byte, src string) (i int, err error) {
	if len(src)%2 != 0 || len(dst) < len(src)/2 {
		return 0, hex.ErrLength
	}

	return hex.Decode(dst, []byte(src))
}

func Range(in string, extra ...int) (out []int) {
	count, lower, upper := 64<<10, -1, -1
	if len(extra) > 0 {
		count = max(1, extra[0])
		if len(extra) > 1 {
			lower = max(0, extra[1])
			if len(extra) > 2 {
				upper = max(0, extra[2])
			}
		}
	}

	list, budget := map[int]struct{}{}, count*4
	for _, part := range strings.Split(in, ",") {
		bounds, start, end := strings.Split(strings.TrimSpace(part), "-"), -1, -1
		if value, err := strconv.Atoi(strings.TrimSpace(bounds[0])); err == nil && value >= 0 {
			start = value
		}
		if start >= 0 && len(bounds) > 1 {
			if value, err := strconv.Atoi(strings.TrimSpace(bounds[1])); err == nil && value >= 0 && value >= start {
				end = value
			}
		}
		if start >= 0 {
			if end < 0 {
				if (lower < 0 || (lower >= 0 && start >= lower)) && (upper < 0 || (upper >= 0 && start <= upper)) {
					list[start] = struct{}{}
				}

			} else {
				if end-start > count {
					end = start + count
				}
				for index := start; index <= end && budget > 0; index++ {
					budget--
					if (lower < 0 || (lower >= 0 && index >= lower)) && (upper < 0 || (upper >= 0 && index <= upper)) {
						list[index] = struct{}{}
					}
				}
			}
		}
		if budget <= 0 || len(list) >= count {
			break
		}
	}
	for value := range list {
		out = append(out, value)
	}
	sort.Ints(out)

	return
}

func Duration(duration time.Duration, extra ...int) (out string) {
	switch {
	case duration < time.Millisecond:
		out = duration.Truncate(time.Microsecond).String()

	case duration < time.Second:
		out = duration.Truncate(time.Millisecond).String()

	default:
		out = duration.Truncate(10 * time.Millisecond).String()
	}
	if len(extra) > 0 {
		return String(out, extra...)
	}

	return
}

func Count(count int64, extra ...int) (out string) {
	if count <= 0 {
		out = "."

	} else {
		out = strconv.FormatInt(count, 10)
	}
	if len(extra) > 0 {
		return String(out, extra...)
	}

	return
}

func Size(size int64, extra ...int) (out string) {
	switch {
	case size < 1<<10:
		out = strconv.FormatInt(size, 10) + " B"

	case size < 1<<20:
		out = strconv.FormatInt(size/(1<<10), 10) + " kiB"

	case size < 10*(1<<20):
		out = strconv.FormatFloat(float64(size)/(1<<20), 'f', 2, 64) + " MiB"

	case size < 100*(1<<20):
		out = strconv.FormatFloat(float64(size)/(1<<20), 'f', 1, 64) + " MiB"

	case size < 1<<30:
		out = strconv.FormatInt(size/(1<<20), 10) + " MiB"

	case size < 10*(1<<30):
		out = strconv.FormatFloat(float64(size)/(1<<30), 'f', 2, 64) + " GiB"

	case size < 100*(1<<30):
		out = strconv.FormatFloat(float64(size)/(1<<30), 'f', 1, 64) + " GiB"

	case size < 1<<40:
		out = strconv.FormatInt(size/(1<<30), 10) + " GiB"

	case size < 10*(1<<40):
		out = strconv.FormatFloat(float64(size)/(1<<40), 'f', 2, 64) + " TiB"

	case size < 100*(1<<40):
		out = strconv.FormatFloat(float64(size)/(1<<40), 'f', 1, 64) + " TiB"

	default:
		out = strconv.FormatInt(size/(1<<40), 10) + " TiB"
	}
	if len(extra) > 0 {
		return String(out, extra...)
	}

	return
}

func Bandwidth(bandwidth int64, extra ...int) (out string) { // in b/s
	switch {
	case bandwidth < 1000:
		out = strconv.FormatInt(bandwidth, 10) + "b/s "

	case bandwidth < 10*1000:
		out = strconv.FormatFloat(float64(bandwidth)/1000, 'f', 2, 64) + "kb/s"

	case bandwidth < 100*1000:
		out = strconv.FormatFloat(float64(bandwidth)/1000, 'f', 1, 64) + "kb/s"

	case bandwidth < 1000*1000:
		out = strconv.FormatInt(bandwidth/1000, 10) + "kb/s"

	case bandwidth < 10*1000*1000:
		out = strconv.FormatFloat(float64(bandwidth)/(1000*1000), 'f', 2, 64) + "Mb/s"

	case bandwidth < 100*1000*1000:
		out = strconv.FormatFloat(float64(bandwidth)/(1000*1000), 'f', 1, 64) + "Mb/s"

	case bandwidth < 1000*1000*1000:
		out = strconv.FormatInt(bandwidth/(1000*1000), 10) + "Mb/s"

	case bandwidth < 10*1000*1000*1000:
		out = strconv.FormatFloat(float64(bandwidth)/(1000*1000*1000), 'f', 2, 64) + "Gb/s"

	case bandwidth < 100*1000*1000*1000:
		out = strconv.FormatFloat(float64(bandwidth)/(1000*1000*1000), 'f', 1, 64) + "Gb/s"

	default:
		out = strconv.FormatInt(bandwidth/(1000*1000*1000), 10) + "Gb/s"

	}
	if len(extra) > 0 {
		return String(out, extra...)
	}

	return
}

func Plural(in string, count int, plural ...string) string {
	if count > 1 {
		if len(plural) > 0 && plural[0] != "" {
			return in + plural[0]
		}
		return in + "s"
	}

	return in
}

type STRFTIME []byte

func Strftime(layout string, base time.Time, extra ...[]byte) (out STRFTIME) {
	if !strings.Contains(layout, "%") {
		return []byte(layout)
	}

	if len(extra) != 0 && extra[0] != nil {
		out = extra[0]

	} else {
		out = make([]byte, 0, 32)
	}

	length, hour, minute, second := len(layout), uint64(base.Hour()), uint64(base.Minute()), uint64(base.Second())
	year, month, day, wday, yday := uint64(base.Year()), uint64(base.Month()), uint64(base.Day()), uint64(base.Weekday()), uint64(base.YearDay())
	nwday := wday
	if nwday == 0 {
		nwday = 7
	}

	for index := 0; index < length; index++ {
		switch layout[index] {
		case '%':
			if index < length-1 {
				c := layout[index+1]
				switch c {
				case 'a':
					out = append(out, days[nwday][:3]...)

				case 'A':
					out = append(out, days[nwday]...)

				case 'b', 'h':
					out = append(out, months[month][:3]...)

				case 'B':
					out = append(out, months[month]...)

				case 'c':
					out = append(out, days[nwday][:3]...)
					out = append(out, ' ')
					out = append(out, months[month][:3]...)
					if day < 10 {
						out = append(out, ' ', ' ')

					} else {
						out = append(out, ' ')
					}
					out = strconv.AppendUint(out, day, 10)
					if hour < 10 {
						out = append(out, ' ', '0')

					} else {
						out = append(out, ' ')
					}
					out = strconv.AppendUint(out, hour, 10)
					if minute < 10 {
						out = append(out, ':', '0')

					} else {
						out = append(out, ':')
					}
					out = strconv.AppendUint(out, minute, 10)
					if second < 10 {
						out = append(out, ':', '0')

					} else {
						out = append(out, ':')
					}
					out = strconv.AppendUint(out, second, 10)
					switch {
					case year < 10:
						out = append(out, ' ', ' ', '0', '0', '0')

					case year < 100:
						out = append(out, ' ', ' ', '0', '0')

					case year < 1000:
						out = append(out, ' ', ' ', '0')

					default:
						out = append(out, ' ')
					}
					out = strconv.AppendUint(out, year, 10)

				case 'C': // TODO remove Int()
					out = append(out, Int(base.Year()/100, 2)...)

				case 'd', 'e':
					if day < 10 {
						if c == 'd' {
							out = append(out, '0')

						} else {
							out = append(out, ' ')
						}
					}
					out = strconv.AppendUint(out, day, 10)

				case 'D':
					out = append(out, base.Format("01/02/06")...)

				case 'F':
					switch {
					case year < 10:
						out = append(out, '0', '0', '0')

					case year < 100:
						out = append(out, '0', '0')

					case year < 1000:
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, year, 10)
					if month < 10 {
						out = append(out, '-', '0')

					} else {
						out = append(out, '-')
					}
					out = strconv.AppendUint(out, month, 10)
					if day < 10 {
						out = append(out, '-', '0')

					} else {
						out = append(out, '-')
					}
					out = strconv.AppendUint(out, day, 10)

				case 'g': // TODO remove ISOWeek()
					year, _ := base.ISOWeek()
					out = append(out, Int(year%100, 2)...)

				case 'G': // TODO remove ISOWeek()
					year, _ := base.ISOWeek()
					out = append(out, Int(year, 4)...)

				case 'H', 'k':
					if hour < 10 {
						if c == 'H' {
							out = append(out, '0')

						} else {
							out = append(out, ' ')
						}
					}
					out = strconv.AppendUint(out, hour, 10)

				case 'I', 'l':
					if hour == 0 || hour == 12 {
						out = append(out, '1', '2')

					} else {
						value := hour % 12
						if value < 10 {
							if c == 'I' {
								out = append(out, '0')

							} else {
								out = append(out, ' ')
							}
						}
						out = strconv.AppendUint(out, value, 10)
					}

				case 'j': // TODO remove Format()
					out = append(out, base.Format("002")...)

				case 'm':
					if month < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, month, 10)

				case 'M':
					if minute < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, minute, 10)

				case 'n':
					out = append(out, '\n')

				case 'p':
					if hour < 12 {
						out = append(out, 'A', 'M')

					} else {
						out = append(out, 'P', 'M')
					}

				case 'P':
					if hour < 12 {
						out = append(out, 'a', 'm')

					} else {
						out = append(out, 'p', 'm')
					}

				case 'r': // TODO remove Format()
					out = append(out, base.Format("03:04:05 PM")...)

				case 'R':
					if hour < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, hour, 10)
					if minute < 10 {
						out = append(out, ':', '0')

					} else {
						out = append(out, ':')
					}
					out = strconv.AppendUint(out, minute, 10)

				case 's':
					out = append(out, strconv.FormatInt(base.Unix(), 10)...)

				case 'S':
					if second < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, second, 10)

				case 't':
					out = append(out, '\t')

				case 'T', 'X':
					if hour < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, hour, 10)
					if minute < 10 {
						out = append(out, ':', '0')

					} else {
						out = append(out, ':')
					}
					out = strconv.AppendUint(out, minute, 10)
					if second < 10 {
						out = append(out, ':', '0')

					} else {
						out = append(out, ':')
					}
					out = strconv.AppendUint(out, second, 10)

				case 'u':
					out = strconv.AppendUint(out, nwday, 10)

				case 'U':
					value := (yday + 6 - wday) / 7
					if value < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, value, 10)

				case 'V':
					_, week := base.ISOWeek()
					out = append(out, Int(week, 2, '0')...)

				case 'w':
					out = strconv.AppendUint(out, wday, 10)

				case 'W':
					value := (yday + 6 - (nwday - 1)) / 7
					if value < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, value, 10)

				case 'x':
					if month < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, month, 10)
					if day < 10 {
						out = append(out, '/', '0')

					} else {
						out = append(out, '/')
					}
					out = strconv.AppendUint(out, day, 10)
					value := year % 100
					if value < 10 {
						out = append(out, '/', '0')

					} else {
						out = append(out, '/')
					}
					out = strconv.AppendUint(out, value, 10)

				case 'y':
					value := year % 100
					if value < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, value, 10)

				case 'Y':
					switch {
					case year < 10:
						out = append(out, '0', '0', '0')

					case year < 100:
						out = append(out, '0', '0')

					case year < 1000:
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, year, 10)

				case 'z':
					_, offset := base.Zone()
					if offset >= 0 {
						out = append(out, '+')

					} else {
						out = append(out, '-')
						offset = -offset
					}

					value := offset / 3600
					if value < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, uint64(value), 10)
					value = (offset - (value * 3600)) / 60
					if value < 10 {
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, uint64(value), 10)

				case 'Z':
					zone, _ := base.Zone()
					out = append(out, zone...)

				case '+': // TODO remove Format()
					out = append(out, base.Format(time.UnixDate)...)

				case '=':
					millisecond := uint64(base.Nanosecond() / 1000000)
					switch {
					case millisecond < 10:
						out = append(out, '0', '0')

					case millisecond < 100:
						out = append(out, '0')
					}
					out = strconv.AppendUint(out, millisecond, 10)

				case '%':
					out = append(out, '%')
				}
				index++
			}

		default:
			out = append(out, layout[index])
		}
	}

	return out
}

func (s STRFTIME) String() string {
	return string(s)
}

const (
	OptionTrim    = 0x01
	OptionSpace   = 0x02
	OptionLower   = 0x04
	OptionUpper   = 0x08
	OptionComment = 0x10
	OptionEmpty   = 0x20
	OptionFirst   = 0x40
	OptionJson    = 0x80
)

func Options(in string) (out int) {
	for _, value := range strings.Fields(strings.ToLower(in)) {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		if value == "trim" || value == "t" {
			out |= OptionTrim
		}
		if value == "space" || value == "s" {
			out |= OptionSpace
		}
		if value == "lower" || value == "l" {
			out |= OptionLower
		}
		if value == "upper" || value == "u" {
			out |= OptionUpper
		}
		if value == "comment" || value == "c" {
			out |= OptionComment
		}
		if value == "empty" || value == "e" {
			out |= OptionEmpty
		}
		if value == "first" || value == "f" {
			out |= OptionFirst
		}
		if value == "json" || value == "j" {
			out |= OptionJson
		}
	}

	return
}

func Transform(in string, options int) string {
	if options&OptionTrim != 0 {
		in = strings.TrimSpace(in)
	}
	if options&OptionSpace != 0 {
		in = Strip(in, " \t\r\n")
	}
	if options&OptionLower != 0 {
		in = strings.ToLower(in)
	}
	if options&OptionUpper != 0 {
		in = strings.ToUpper(in)
	}
	if options&OptionComment != 0 {
		if index := strings.Index(in, "#"); index >= 0 {
			in = in[:index]
		}
	}

	return in
}

func Reverse(in string) string {
	runes := []rune(in)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}
