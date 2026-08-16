package acl

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type timeRange struct {
	dates [2]time.Time
	days  [2]int
	times [2]int
}

var (
	dateMatcher = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})?(-)?(\d{4}-\d{2}-\d{2})?$`)
	dayMatcher  = regexp.MustCompile(`^(mon|tue|wed|thu|fri|sat|sun)?(-)?(mon|tue|wed|thu|fri|sat|sun)?$`)
	timeMatcher = regexp.MustCompile(`^(?:(\d{2}):(\d{2}))?(-)?(?:(\d{2}):(\d{2}))?$`)
	days        = map[string]int{"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
)

func Ranges(now time.Time, values []string) bool {
	if len(values) == 0 {
		return false
	}
	ranges := []timeRange{}
	for _, path := range values {
		entry, invalid := timeRange{times: [2]int{-1, -1}}, false
		for _, value := range strings.Fields(path) {
			if captures := dateMatcher.FindStringSubmatch(value); len(captures) == 4 {
				if captures[1] == "" && captures[3] == "" {
					invalid = true
				}
				lower, err1 := time.Parse("2006-01-02", captures[1])
				upper, err2 := time.Parse("2006-01-02", captures[3])
				if (captures[1] != "" && err1 != nil) || (captures[3] != "" && err2 != nil) {
					invalid = true
				}

				if captures[2] == "" {
					entry.dates[0], entry.dates[1] = lower, lower.Add(24*time.Hour)

				} else {
					if captures[1] != "" {
						entry.dates[0] = lower
					}
					if captures[3] != "" {
						entry.dates[1] = upper.Add(24 * time.Hour)
					}
				}

			} else if captures := dayMatcher.FindStringSubmatch(strings.ToLower(value)); len(captures) == 4 {
				lower, upper := days[captures[1]], days[captures[3]]
				if (lower == 0 && upper == 0) || (lower != 0 && upper != 0 && upper < lower) {
					invalid = true
				}

				if captures[2] == "" {
					entry.days[0], entry.days[1] = lower, lower

				} else {
					if lower != 0 {
						entry.days[0] = lower
					}
					if upper != 0 {
						entry.days[1] = upper
					}
				}

			} else if captures := timeMatcher.FindStringSubmatch(value); len(captures) == 6 {
				lower, upper := -1, -1
				if captures[1] != "" {
					hour, err := strconv.ParseInt(captures[1], 10, 64)
					if err != nil || hour < 0 || hour > 23 {
						invalid = true
					}
					minute, err := strconv.ParseInt(captures[2], 10, 64)
					if err != nil || minute < 0 || minute > 59 {
						invalid = true
					}
					lower = int(hour)*3600 + int(minute)*60
				}
				if captures[4] != "" {
					hour, err := strconv.ParseInt(captures[4], 10, 64)
					if err != nil || hour < 0 || hour > 23 {
						invalid = true
					}
					minute, err := strconv.ParseInt(captures[5], 10, 64)
					if err != nil || minute < 0 || minute > 59 {
						invalid = true
					}
					upper = int(hour)*3600 + int(minute)*60
				}
				if (lower == -1 && upper == -1) || (lower != -1 && upper != -1 && upper < lower) {
					invalid = true
				}

				if captures[3] == "" {
					entry.times[0], entry.times[1] = lower, lower+60

				} else {
					if lower != -1 {
						entry.times[0] = lower
					}
					if upper != -1 {
						entry.times[1] = upper + 60
					}
				}

			} else {
				invalid = true
			}

			if invalid {
				break
			}
		}

		if !invalid && ((!entry.dates[0].IsZero() || !entry.dates[1].IsZero()) || (entry.days[0] != 0 || entry.days[1] != 0) || (entry.times[0] != 0 || entry.times[1] != 0)) {
			ranges = append(ranges, entry)
		}
	}

	now = now.UTC()
	day, stamp := int(now.Weekday()), now.Hour()*3600+now.Minute()*60+now.Second()
	if day == 0 {
		day = 7
	}
	for _, entry := range ranges {
		if (!entry.dates[0].IsZero() && now.Sub(entry.dates[0]) < 0) || (!entry.dates[1].IsZero() && now.Sub(entry.dates[1]) >= 0) ||
			(entry.days[0] != 0 && day < entry.days[0]) || (entry.days[1] != 0 && day > entry.days[1]) ||
			(entry.times[0] != -1 && stamp < entry.times[0]) || (entry.times[1] != -1 && stamp >= entry.times[1]) {
			continue
		}
		return true
	}

	return false
}
