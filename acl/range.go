package acl

import (
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
)

type timeRange struct {
	dates [2]time.Time
	days  [2]int
	times [2]int
}

func Ranges(in time.Time, values []string, fallback bool) (match bool, index int) {
	if len(values) > 0 {
		ranges, matcher1, matcher2, matcher3, days := []timeRange{},
			rcache.Get(`^(\d{4}-\d{2}-\d{2})?-(\d{4}-\d{2}-\d{2})?$`),
			rcache.Get(`^(mon|tue|wed|thu|fri|sat|sun)?-(mon|tue|wed|thu|fri|sat|sun)?$`),
			rcache.Get(`^(?:(\d{2}):(\d{2})(?::(\d{2}))?)?-(?:(\d{2}):(\d{2})(?::(\d{2}))?)?$`),
			map[string]int{"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
		for _, path := range values {
			entry := timeRange{}
			for _, value := range strings.Split(path, " ") {
				if captures := matcher1.FindStringSubmatch(value); len(captures) == 3 {
					if value, err := time.Parse("2006-01-02", captures[1]); err == nil {
						entry.dates[0] = value
					}
					if value, err := time.Parse("2006-01-02", captures[2]); err == nil {
						entry.dates[1] = value.Add(86399 * time.Second)
					}

				} else if captures := matcher2.FindStringSubmatch(strings.ToLower(value)); len(captures) == 3 {
					entry.days[0], entry.days[1] = days[captures[1]], days[captures[2]]

				} else if captures := matcher3.FindStringSubmatch(value); len(captures) == 7 {
					hour, _ := strconv.ParseInt(captures[1], 10, 64)
					minute, _ := strconv.ParseInt(captures[2], 10, 64)
					second, _ := strconv.ParseInt(captures[3], 10, 64)
					entry.times[0] = int(hour)*3600 + int(minute)*60 + int(second)
					hour, _ = strconv.ParseInt(captures[4], 10, 64)
					minute, _ = strconv.ParseInt(captures[5], 10, 64)
					second, _ = strconv.ParseInt(captures[6], 10, 64)
					entry.times[1] = int(hour)*3600 + int(minute)*60 + int(second)
				}
			}
			ranges = append(ranges, entry)
		}
		now := in.UTC()
		day, stamp := int(now.Weekday()), now.Hour()*3600+now.Minute()*60+now.Second()
		if day == 0 {
			day = 7
		}
		for _, entry := range ranges {
			if (!entry.dates[0].IsZero() && now.Sub(entry.dates[0]) < 0) || (!entry.dates[1].IsZero() && now.Sub(entry.dates[1]) > 0) ||
				(entry.days[0] != 0 && day < entry.days[0]) || (entry.days[1] != 0 && day > entry.days[1]) ||
				(entry.times[0] != 0 && stamp < entry.times[0]) || (entry.times[1] != 0 && stamp > entry.times[1]) {
				index++
				continue
			}
			return true, index
		}
		return false, -1
	}
	return fallback, -1
}

func RangesConfig(in time.Time, config *uconfig.UConfig, path string, fallback bool) (match bool, index int) {
	return Ranges(in, config.Strings(path), fallback)
}
