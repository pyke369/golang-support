package ustr

import (
	"errors"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return errors.New(msg + ": " + err.Error())
}

func Bool(in bool) (out string) {
	if in {
		return "true"
	}
	return "false"
}

func Int(in int, extra ...int) (out string) {
	out = strconv.Itoa(in)
	if in >= 0 && len(extra) > 0 {
		size := max(0, extra[0])
		if len(out) < size {
			pad := "0"
			if len(extra) > 1 && extra[1] != 0 {
				pad = " "
			}
			out = strings.Repeat(pad, size-len(out)) + out
		}
	}
	return
}

func String(in string, extra ...int) (out string) {
	out = in
	size, left := 0, false
	if len(extra) > 0 {
		if extra[0] < 0 {
			left = true
			size, left = -extra[0], true
		} else {
			size = extra[0]
		}
	}
	if len(out) < size {
		if left {
			out += strings.Repeat(" ", size-len(out))
		} else {
			out = strings.Repeat(" ", size-len(out)) + out
		}
	}
	if len(extra) > 1 && extra[1] > 0 && len(out) > extra[1] {
		out = out[:extra[1]]
	}
	return
}

func Hex(in []byte, extra ...string) (out string) {
	if len(in) != 0 {
		separator, hex := []byte{}, "0123456789abcdef"
		if len(extra) != 0 {
			separator = []byte(extra[0])
		}
		length := len(in)
		buffer := make([]byte, 0, length+(len(separator))*(length-1))
		for index, value := range in {
			buffer = append(buffer, hex[value>>4], hex[value&0x0f])
			if index < length-1 {
				buffer = append(buffer, separator...)
			}
		}
		out = unsafe.String(unsafe.SliceData(buffer), len(buffer))
	}
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
	out, length := make([]byte, 0, 128), len(layout)
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
						day -= 1
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
