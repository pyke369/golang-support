package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/mstore"
	"github.com/pyke369/golang-support/rcache"
)

func usage(status int) {
	fmt.Fprintf(os.Stderr, "usage: mstore <action> [<parameter> ...]\n\n"+
		"help\n"+
		"  show this help screen\n\n"+
		"metadata <store> <metric>\n"+
		"  display metric metadata\n\n"+
		"export <store> <metric>\n"+
		"  export metric metadata and values\n\n"+
		"import <store> <metric> <data>\n"+
		"  import metric metadata and values\n\n"+
		"extend <store> <metric> <mode>[@<size>[@<description>]][,...]\n"+
		"  add new column(s) to existing metric (preserving values)\n\n"+
		"query <store> <metric> <start|-> <end|-> <interval|-> <aggregate>[,<aggregate>...]\n"+
		"  query metric aggregates (each <aggregate> in the <index>@<mode>[@<min|divider>[@<max|neg-divider|percentile>]] format)\n"+
		"\n")
	os.Exit(status)
}

func bail(err error, status int) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(status)
	}
}

func decode(input string, start, end time.Time) (output time.Time, err error) {
	if captures := rcache.Get(`^\s*(now|end|start)\s*(?:(\+|\-)\s*(\d+)\s*(mo(?:nths?)?|s(?:ec(?:onds?)?)?|m(?:in(?:utes?)?)?|h(?:ours?)?|d(?:ays?)?|w(?:eeks?)?))?\s*$`).
		FindStringSubmatch(strings.ToLower(input)); captures != nil {
		switch captures[1] {
		case "now":
			output = time.Now()
		case "start":
			output = start
		case "end":
			output = end
		}
		if amount, _ := strconv.Atoi(captures[3]); amount != 0 {
			direction := +1
			if captures[2] == "-" {
				direction = -1
			}
			switch true {
			case len(captures[4]) >= 2 && captures[4][:2] == "mo":
				output = output.AddDate(0, direction*amount, 0)
			case captures[4][0] == 's':
				output = output.Add(time.Duration(direction*amount) * time.Second)
			case captures[4][0] == 'm':
				output = output.Add(time.Duration(direction*amount) * time.Minute)
			case captures[4][0] == 'h':
				output = output.Add(time.Duration(direction*amount) * time.Hour)
			case captures[4][0] == 'd':
				output = output.AddDate(0, 0, direction*amount)
			case captures[4][0] == 'w':
				output = output.AddDate(0, 0, direction*amount*7)
			}
		}
		return
	}
	return time.Unix(0, 0), fmt.Errorf("no match")
}

func main() {
	if len(os.Args) < 2 {
		usage(1)
	}
	switch os.Args[1] {
	case "help":
		usage(0)

	case "metadata":
		if len(os.Args) < 4 {
			usage(1)
		}
		metrics, err := mstore.NewStore(os.Args[2], true)
		bail(err, 3)
		metadata, err := metrics.Metric(os.Args[3]).Metadata()
		bail(err, 4)
		output, err := json.MarshalIndent(metadata, "", "  ")
		bail(err, 5)
		fmt.Printf("%s\n", output)

	case "export":
		if len(os.Args) < 4 {
			usage(1)
		}
		metrics, err := mstore.NewStore(os.Args[2], true)
		bail(err, 3)
		export, err := metrics.Metric(os.Args[3]).Export()
		bail(err, 4)
		metadata, err := json.MarshalIndent(export["metadata"], "  ", "  ")
		bail(err, 5)
		columns, data, lines := j.Slice(j.Map(export["metadata"])["columns"]), j.Slice(export["values"]), []string{
			`{`,
			`  "metadata": ` + string(metadata) + `,`,
			`  "values": [`,
		}
		for dindex, value := range data {
			if values := j.Slice(value); len(values) == len(columns)+1 {
				at := time.Unix(int64(j.Number(values[0])), 0).UTC()
				line := fmt.Sprintf(`    ["%s",`, at.Format(time.DateTime))
				for vindex, value := range values[1:] {
					switch j.String(j.Map(columns[vindex])["mode"]) {
					case "gauge", "counter", "increment":
						line += fmt.Sprintf(`%d`, value)
					case "text", "binary":
						line += fmt.Sprintf(`"%v"`, value)
					}
					if vindex < len(values)-2 {
						line += `,`
					}
				}
				if dindex < len(data)-1 {
					line += `],`
				} else {
					line += `]`
				}
				lines = append(lines, line)
			}
		}
		lines = append(lines, `  ]`)
		lines = append(lines, `}`)
		fmt.Printf("%s\n", strings.Join(lines, "\n"))

	case "import":
		if len(os.Args) < 5 {
			usage(1)
		}
		content, err := os.ReadFile(os.Args[4])
		bail(err, 3)
		data := map[string]any{}
		bail(json.Unmarshal(content, &data), 4)
		metrics, err := mstore.NewStore(os.Args[2])
		bail(err, 5)
		bail(metrics.Metric(os.Args[3]).Import(data), 6)

	case "extend":
		if len(os.Args) < 5 {
			usage(1)
		}
		metrics, err := mstore.NewStore(os.Args[2])
		bail(err, 3)
		export, err := metrics.Metric(os.Args[3]).Export()
		bail(err, 4)
		columns := j.Slice(j.Map(export["metadata"])["columns"])
		for _, value := range strings.Split(os.Args[4], ",") {
			value = strings.TrimSpace(value)
			parts := strings.Split(value, "@")
			parts[0] = strings.ToLower(strings.TrimSpace(parts[0]))
			if mstore.ModeIndexes[parts[0]] == 0 {
				bail(fmt.Errorf("invalid column type \"%s\"", parts[0]), 5)
			}
			size, description := 0, ""
			if len(parts) > 1 {
				size, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
				if size != 1 && size != 2 && size != 4 && size != 8 {
					bail(fmt.Errorf("invalid column size %d", size), 5)
				}
				if len(parts) > 2 {
					description = strings.TrimSpace(parts[2])
				}
			}
			columns = append(columns, map[string]any{"mode": parts[0], "size": size, "description": description})
		}
		j.Map(export["metadata"])["columns"] = columns
		now := time.Now().UnixNano() / int64(time.Millisecond)
		target := fmt.Sprintf("%s_%d", os.Args[3], now)
		bail(metrics.Metric(target+"_ext").Import(export), 6)
		bail(metrics.Rename(os.Args[3], target), 7)
		bail(metrics.Rename(target+"_ext", os.Args[3]), 8)

	case "query":
		if len(os.Args) < 8 {
			usage(1)
		}
		metrics, err := mstore.NewStore(os.Args[2], true)
		bail(err, 3)
		start, end := time.Now().Add(-time.Hour), time.Now()
		if value, err := time.Parse(time.DateTime, os.Args[4]); err == nil {
			start = value
		}
		if value, err := time.Parse(time.DateTime, os.Args[5]); err == nil {
			end = value
		}
		if value, err := decode(os.Args[5], start, end); err == nil {
			end = value
		}
		if value, err := decode(os.Args[4], start, end); err == nil {
			start = value
		}
		if end.Before(start) {
			bail(fmt.Errorf("invalid timerange [ %s - %s ]", start.Format(time.DateTime), end.Format(time.DateTime)), 4)
		}
		interval, _ := strconv.ParseInt(os.Args[6], 10, 64)
		if interval <= 0 {
			interval = int64(end.Sub(start) / time.Second)
		}
		if interval <= 0 {
			bail(fmt.Errorf("invalid interval %d", interval), 5)
		}
		columns := [][]int64{}
		for _, value := range strings.Split(os.Args[7], ",") {
			value = strings.TrimSpace(value)
			parts := strings.Split(value, "@")
			if len(parts) < 2 {
				bail(fmt.Errorf("invalid aggregate format \"%s\"", value), 6)
			}
			index, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			bail(err, 7)
			value = strings.ToLower(strings.TrimSpace(parts[1]))
			mode := mstore.AggregateIndexes[value]
			if mode == 0 {
				bail(fmt.Errorf("invalid aggregate mode \"%s\"", value), 8)
			}
			column := []int64{index, mode}
			if len(parts) > 2 {
				min, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
				bail(err, 9)
				column = append(column, min)
			}
			if len(parts) > 3 {
				max, err := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
				bail(err, 10)
				column = append(column, max)
			}
			columns = append(columns, column)
		}
		if len(columns) == 0 {
			bail(fmt.Errorf("no valid aggregate specified"), 11)
		}
		watch := time.Now()
		result, err := metrics.Metric(os.Args[3]).Get(start, end, interval, columns, true)
		bail(err, 12)
		result["query"] = map[string]any{
			"start":    start.Format(time.DateTime),
			"end":      end.Format(time.DateTime),
			"interval": interval,
			"duration": time.Since(watch) / time.Microsecond,
		}
		content, err := json.MarshalIndent(result, "", "  ")
		bail(err, 13)
		fmt.Printf("%s\n", content)

	default:
		usage(2)
	}
}
