package ustr

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

var (
	bools = [][2]string{
		[2]string{"false", "true"},
		[2]string{"no", "yes"},
		[2]string{"off", "on"},
		[2]string{"failure", "success"},
		[2]string{"0", "1"},
	}
	hex = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
)

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return errors.New(msg + ": " + err.Error())
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
	value, size, pad := strconv.Itoa(in), 0, byte(' ')
	if len(extra) > 0 {
		size = extra[0]
		if len(extra) > 1 && size >= 0 {
			pad = '0'
		}
	}
	length, usize := len(value), size
	if usize < 0 {
		usize = -usize
	}
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
	return unsafe.String(unsafe.SliceData(out), len(out))
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
		usize = -usize
	}
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
	return unsafe.String(unsafe.SliceData(out), len(out))
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
		out[offset], out[offset+1] = hex[in[index]>>4], hex[in[index]&0x0f]
		offset += 2
		if pad != 0 && index < length-1 {
			out[offset] = pad
			offset++
		}
	}
	return unsafe.String(unsafe.SliceData(out), len(out))
}

func Range(in string) (out []int) {
	list := map[int]struct{}{}
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
				list[start] = struct{}{}
			} else {
				for index := start; index <= end; index++ {
					list[index] = struct{}{}
				}
			}
		}
	}
	for value := range list {
		out = append(out, value)
	}
	sort.Ints(out)
	return
}

func Duration(duration time.Duration) string {
	if duration < time.Millisecond {
		return duration.Truncate(time.Microsecond).String()
	}
	if duration < time.Second {
		return duration.Truncate(time.Millisecond).String()
	}
	return duration.Truncate(10 * time.Millisecond).String()
}

func Strftime(layout string, base time.Time) string {
	length, out := len(layout), make([]byte, 0, 128)
	for index := 0; index < length; index++ {
		switch layout[index] {
		case '%':
			if index < length-1 {
				switch layout[index+1] {
				case 'a':
					out = append(out, base.Format("Mon")...)

				case 'A':
					out = append(out, base.Format("Monday")...)

				case 'b', 'h':
					out = append(out, base.Format("Jan")...)

				case 'B':
					out = append(out, base.Format("January")...)

				case 'c':
					out = append(out, base.Format("Mon Jan 2 15:04:05 2006")...)

				case 'C':
					out = append(out, Int(base.Year()/100, 2)...)

				case 'd':
					out = append(out, base.Format("02")...)

				case 'D':
					out = append(out, base.Format("01/02/06")...)

				case 'e':
					out = append(out, base.Format("_2")...)

				case 'f':
					out = append(out, Int(base.Nanosecond()/1000, 6)...)

				case 'F':
					out = append(out, base.Format("2006-01-02")...)

				case 'g':
					year, _ := base.ISOWeek()
					out = append(out, Int(year%100, 2)...)

				case 'G':
					year, _ := base.ISOWeek()
					out = append(out, Int(year, 4)...)

				case 'H':
					out = append(out, base.Format("15")...)

				case 'I':
					out = append(out, base.Format("03")...)

				case 'j':
					out = append(out, base.Format("002")...)

				case 'k':
					out = append(out, Int(base.Hour(), 2, 1)...)

				case 'l':
					if base.Hour() == 0 || base.Hour() == 12 {
						out = append(out, "12"...)
					} else {
						out = append(out, Int(base.Hour()%12, 2, 1)...)
					}

				case 'm':
					out = append(out, base.Format("01")...)

				case 'M':
					out = append(out, base.Format("04")...)

				case 'n':
					out = append(out, '\n')

				case 'p':
					out = append(out, base.Format("PM")...)

				case 'P':
					out = append(out, base.Format("pm")...)

				case 'r':
					out = append(out, base.Format("03:04:05 PM")...)

				case 'R':
					out = append(out, base.Format("15:04")...)

				case 's':
					out = append(out, strconv.FormatInt(base.Unix(), 10)...)

				case 'S':
					out = append(out, base.Format("05")...)

				case 't':
					out = append(out, '\t')

				case 'T':
					out = append(out, base.Format("15:04:05")...)

				case 'u':
					day := base.Weekday()
					if day == 0 {
						day = 7
					}
					out = append(out, strconv.Itoa(int(day))...)

				case 'U':
					out = append(out, Int((base.YearDay()+6-int(base.Weekday()))/7, 2)...)

				case 'V':
					_, week := base.ISOWeek()
					out = append(out, Int(week, 2)...)

				case 'w':
					out = append(out, strconv.Itoa(int(base.Weekday()))...)

				case 'W':
					day := int(base.Weekday())
					if day == 0 {
						day = 6
					} else {
						day--
					}
					out = append(out, Int((base.YearDay()+6-day)/7, 2)...)

				case 'x':
					out = append(out, base.Format("01/02/06")...)

				case 'X':
					out = append(out, base.Format("15:04:05")...)

				case 'y':
					out = append(out, base.Format("06")...)

				case 'Y':
					out = append(out, base.Format("2006")...)

				case 'z':
					out = append(out, base.Format("-0700")...)

				case 'Z':
					out = append(out, base.Format("MST")...)

				case '+':
					out = append(out, base.Format(time.UnixDate)...)

				case '%':
					out = append(out, '%')
				}
				index++
			}

		default:
			out = append(out, layout[index])
		}
	}
	return unsafe.String(unsafe.SliceData(out), len(out))
}

const (
	OptionTrim  = 0x01
	OptionSpace = 0x02
	OptionLower = 0x04
	OptionUpper = 0x08
	OptionEmpty = 0x10
	OptionFirst = 0x20
	OptionJSON  = 0x40
)

func Options(in string) (out int) {
	for _, value := range strings.Fields(strings.ToLower(in)) {
		value = strings.TrimSpace(value)
		if strings.HasPrefix("trim", value) {
			out |= OptionTrim
		}
		if strings.HasPrefix("space", value) {
			out |= OptionSpace
		}
		if strings.HasPrefix("lower", value) {
			out |= OptionLower
		}
		if strings.HasPrefix("upper", value) {
			out |= OptionUpper
		}
		if strings.HasPrefix("empty", value) {
			out |= OptionEmpty
		}
		if strings.HasPrefix("first", value) {
			out |= OptionFirst
		}
		if strings.HasPrefix("json", value) {
			out |= OptionJSON
		}
	}
	return
}

func Transform(in string, options int) string {
	if options&OptionTrim != 0 {
		in = strings.TrimSpace(in)
	}
	if options&OptionSpace != 0 {
		in = strings.ReplaceAll(strings.ReplaceAll(in, " ", ""), "\t", "")
	}
	if options&OptionLower != 0 {
		in = strings.ToLower(in)
	}
	if options&OptionUpper != 0 {
		in = strings.ToUpper(in)
	}
	return in
}
