package main

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/mstore"
	"github.com/pyke369/golang-support/rcache"
)

func usage(status int) {
	os.Stderr.WriteString("usage: mstore <action> [<parameter> ...]\n\n" +
		"help\n" +
		"  show this help screen\n\n" +
		"metadata <store> <metric>\n" +
		"  display metric metadata\n\n" +
		"values <store> <metric>\n" +
		"  display values in CSV format\n\n" +
		"export <store> <metric>\n" +
		"  export metric metadata and values\n\n" +
		"import <store> <metric> <data>\n" +
		"  import metric metadata and values\n\n" +
		"extend <store> <metric> <mode>[@<size>[@<description>]][,...]\n" +
		"  add new column(s) to existing metric (preserving values)\n\n" +
		"query <store> <metric> <start|-> <end|-> <interval|-> <aggregate>[,<aggregate>...]\n" +
		"  query metric aggregates (each <aggregate> in the <index>@<mode>[@<min|divider>[@<max|neg-divider|percentile>]] format)\n" +
		"\n")
	os.Exit(status)
}

func bail(err error, status int) {
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(status)
	}
}

func decode(in string, start, end time.Time) (out time.Time, err error) {
	if captures := rcache.Get(`^\s*(now|end|start)\s*(?:(\+|\-)\s*(\d+)\s*(mo(?:nths?)?|s(?:ec(?:onds?)?)?|m(?:in(?:utes?)?)?|h(?:ours?)?|d(?:ays?)?|w(?:eeks?)?))?\s*$`).
		FindStringSubmatch(strings.ToLower(in)); captures != nil {
		switch captures[1] {
		case "now":
			out = time.Now()

		case "start":
			out = start

		case "end":
			out = end
		}
		if amount, _ := strconv.Atoi(captures[3]); amount != 0 {
			direction := +1
			if captures[2] == "-" {
				direction = -1
			}
			switch {
			case len(captures[4]) >= 2 && captures[4][:2] == "mo":
				out = out.AddDate(0, direction*amount, 0)

			case captures[4][0] == 's':
				out = out.Add(time.Duration(direction*amount) * time.Second)

			case captures[4][0] == 'm':
				out = out.Add(time.Duration(direction*amount) * time.Minute)

			case captures[4][0] == 'h':
				out = out.Add(time.Duration(direction*amount) * time.Hour)

			case captures[4][0] == 'd':
				out = out.AddDate(0, 0, direction*amount)

			case captures[4][0] == 'w':
				out = out.AddDate(0, 0, direction*amount*7)
			}
		}
		return
	}
	return time.Unix(0, 0), errors.New("no match")
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
		out, err := json.MarshalIndent(metadata, "", "  ")
		bail(err, 5)
		os.Stdout.Write(out)
		os.Stdout.WriteString("\n")

	case "values":
		if len(os.Args) < 4 {
			usage(1)
		}
		metrics, err := mstore.NewStore(os.Args[2], true)
		bail(err, 3)
		export, err := metrics.Metric(os.Args[3]).Export()
		bail(err, 4)
		columns, data, names := j.Slice(j.Map(export["metadata"])["columns"]), j.Slice(export["values"]), []string{"date"}
		for index, column := range columns {
			column := j.Map(column)
			if description := j.String(column["description"]); description != "" && !strings.HasSuffix(description, "...") {
				hide := true
			done:
				for _, line := range data {
					value := j.Slice(line)[index+1]
					switch j.String(column["mode"]) {
					case "gauge", "counter", "increment":
						if j.Number(value) != 0 {
							hide = false
							break done
						}
					case "text", "binary":
						if j.String(value) != "" {
							hide = false
							break done
						}
					}
				}
				if hide {
					columns[index].(map[string]any)["description"] = ""
				} else {
					names = append(names, description)
				}
			}
		}
		os.Stdout.WriteString(strings.Join(names, ",") + "\n")
		for _, line := range j.Slice(export["values"]) {
			values := []string{}
			for index, value := range j.Slice(line) {
				if index == 0 {
					values = append(values, time.Unix(int64(j.Number(value)), 0).UTC().Format(time.DateTime))
				} else if index <= len(columns) {
					column := j.Map(columns[index-1])
					if description := j.String(column["description"]); description != "" {
						switch j.String(column["mode"]) {
						case "gauge", "counter", "increment":
							values = append(values, strconv.FormatInt(int64(j.Number(value)), 10))
						case "text", "binary":
							values = append(values, `"`+j.String(value)+`"`)
						}
					}
				}
			}
			os.Stdout.WriteString(strings.Join(values, ",") + "\n")
		}

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
			"{",
			`  "metadata": ` + string(metadata) + ",",
			`  "values": [`,
		}
		for dindex, value := range data {
			values := j.Slice(value)
			if len(values) != len(columns)+1 {
				continue
			}
			at := time.Unix(int64(j.Number(values[0])), 0).UTC()
			line := `    ["` + at.Format(time.DateTime) + `",`
			for vindex, value := range values[1:] {
				switch j.String(j.Map(columns[vindex])["mode"]) {
				case "gauge", "counter", "increment":
					line += strconv.FormatInt(int64(j.Number(value)), 10)

				case "text", "binary":
					line += `"` + j.String(value) + `"`
				}
				if vindex < len(values)-2 {
					line += ","
				}
			}
			if dindex < len(data)-1 {
				line += "],"
			} else {
				line += "]"
			}
			lines = append(lines, line)
		}
		lines = append(lines, "  ]", "}")
		os.Stdout.WriteString(strings.Join(lines, "\n"))
		os.Stdout.WriteString("\n")

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
				bail(errors.New("invalid column type "+parts[0]), 5)
			}
			size, description := 0, ""
			if len(parts) > 1 {
				size, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
				if size != 1 && size != 2 && size != 4 && size != 8 {
					bail(errors.New("invalid column size "+strconv.Itoa(size)), 5)
				}
				if len(parts) > 2 {
					description = strings.TrimSpace(parts[2])
				}
			}
			columns = append(columns, map[string]any{"mode": parts[0], "size": size, "description": description})
		}
		j.Map(export["metadata"])["columns"] = columns
		now := time.Now().UnixNano() / int64(time.Millisecond)
		target := os.Args[3] + "_" + strconv.FormatInt(now, 10)
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
			bail(errors.New("invalid timerange [ "+start.Format(time.DateTime)+" - "+end.Format(time.DateTime)+" ]"), 4)
		}
		interval, _ := strconv.ParseInt(os.Args[6], 10, 64)
		if interval <= 0 {
			interval = int64(end.Sub(start) / time.Second)
		}
		if interval <= 0 {
			bail(errors.New("invalid interval "+strconv.FormatInt(interval, 10)), 5)
		}
		columns := [][]int64{}
		for _, value := range strings.Split(os.Args[7], ",") {
			value = strings.TrimSpace(value)
			parts := strings.Split(value, "@")
			if len(parts) < 2 {
				bail(errors.New("invalid aggregate format "+value), 6)
			}
			index, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			bail(err, 7)
			value = strings.ToLower(strings.TrimSpace(parts[1]))
			mode := mstore.AggregateIndexes[value]
			if mode == 0 {
				bail(errors.New("invalid aggregate mode "+value), 8)
			}
			column := []int64{index, mode}
			if len(parts) > 2 {
				value, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
				bail(err, 9)
				column = append(column, value)
			}
			if len(parts) > 3 {
				value, err := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
				bail(err, 10)
				column = append(column, value)
			}
			columns = append(columns, column)
		}
		if len(columns) == 0 {
			bail(errors.New("no valid aggregate specified"), 11)
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
		os.Stdout.Write(content)
		os.Stdout.WriteString("\n")

	default:
		usage(2)
	}
}
