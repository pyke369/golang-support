package acl

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/uconfig"
)

type timeRange struct {
	dates [2]time.Time
	days  [2]int
	times [2]int
}

var (
	dateMatcher = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})?-(\d{4}-\d{2}-\d{2})?$`)
	dayMatcher  = regexp.MustCompile(`^(mon|tue|wed|thu|fri|sat|sun)?-(mon|tue|wed|thu|fri|sat|sun)?$`)
	timeMatcher = regexp.MustCompile(`^(?:(\d{2}):(\d{2})(?::(\d{2}))?)?-(?:(\d{2}):(\d{2})(?::(\d{2}))?)?$`)
	days        = map[string]int{"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
)

func Ranges(in time.Time, values []string) bool {
	if len(values) == 0 {
		return false
	}
	ranges := []timeRange{}
	for _, path := range values {
		entry := timeRange{}
		for _, value := range strings.Split(path, " ") {
			if captures := dateMatcher.FindStringSubmatch(value); len(captures) == 3 {
				if value, err := time.Parse("2006-01-02", captures[1]); err == nil {
					entry.dates[0] = value
				}
				if value, err := time.Parse("2006-01-02", captures[2]); err == nil {
					entry.dates[1] = value.Add(86399 * time.Second)
				}

			} else if captures := dayMatcher.FindStringSubmatch(strings.ToLower(value)); len(captures) == 3 {
				entry.days[0], entry.days[1] = days[captures[1]], days[captures[2]]

			} else if captures := timeMatcher.FindStringSubmatch(value); len(captures) == 7 {
				hour, _ := strconv.ParseInt(captures[1], 10, 64)
				hour = max(0, min(23, hour))
				minute, _ := strconv.ParseInt(captures[2], 10, 64)
				minute = max(0, min(59, minute))
				second, _ := strconv.ParseInt(captures[3], 10, 64)
				second = max(0, min(59, second))
				entry.times[0] = int(hour)*3600 + int(minute)*60 + int(second)
				hour, _ = strconv.ParseInt(captures[4], 10, 64)
				hour = max(0, min(23, hour))
				minute, _ = strconv.ParseInt(captures[5], 10, 64)
				minute = max(0, min(59, minute))
				second, _ = strconv.ParseInt(captures[6], 10, 64)
				second = max(0, min(59, second))
				entry.times[1] = int(hour)*3600 + int(minute)*60 + int(second)
			}
		}
		if (!entry.dates[0].IsZero() || !entry.dates[1].IsZero()) ||
			(entry.days[0] != 0 || entry.days[1] != 0) ||
			(entry.times[0] != 0 || entry.times[1] != 0) {
			ranges = append(ranges, entry)
		}
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
			continue
		}
		return true
	}

	return false
}

func RangesConfig(in time.Time, config *uconfig.UConfig, path string) bool {
	return Ranges(in, config.Strings(path))
}
