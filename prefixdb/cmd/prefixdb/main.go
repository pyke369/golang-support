package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/prefixdb"
)

type LOCATION struct {
	ContinentCode string
	ContinentName string
	CountryCode   string
	CountryName   string
	RegionCode    string
	RegionName    string
	StateCode     string
	StateName     string
	CityName      string
	TimeZone      string
	InEurope      bool
}

type OUI struct {
	Mac     string `json:"oui"`
	Company string `json:"companyName"`
}

var (
	csvMatcher  = regexp.MustCompile(`(?:,|\n|^)("(?:(?:"")*[^"]*)*"|[^",\n]*|(?:\n|$))`)
	jsonMatcher = regexp.MustCompile(`^(\S+)(?:\s(\{.+?\}))?$`)
	ouiMatcher  = regexp.MustCompile(`(?i)^([0-9a-f]{1,2})(?::([0-9a-f]{1,2}))?(?::([0-9a-f]{1,2}))?(?::([0-9a-f]{1,2}))?(?::([0-9a-f]{1,2}))?(?::([0-9a-f]{1,2}))?$`)
	pfdb        = prefixdb.New()
	client      = &http.Client{Timeout: 5 * time.Second}
)

func size(in int) string {
	if in < 1024*1024 {
		return fmt.Sprintf("%.1fkB", float64(in)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(in)/(1024*1024))
}

func mkjson() {
	for index := 3; index < len(os.Args); index++ {
		count := 0
		if handle, err := os.Open(os.Args[index]); err == nil {
			reader := bufio.NewReader(handle)
			last := time.Now()
			start := last
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					if fields := jsonMatcher.FindStringSubmatch(strings.TrimSpace(line)); fields != nil {
						if prefix, err := netip.ParsePrefix(fields[1]); err == nil {
							data := map[string]any{}
							json.Unmarshal([]byte(fields[2]), &data)
							pfdb.Add(prefix, data, [][]string{[]string{"key1", "key2"}})
							count++
						}
					}
				}
				if now := time.Now(); now.Sub(last) >= 250*time.Millisecond {
					last = now
					fmt.Fprintf(os.Stderr, "\radding prefixes  [%s] %d", os.Args[index], count)
				}
			}
			handle.Close()
			fmt.Fprintf(os.Stderr, "\radded prefixes   [%s] (%.3fs - %d entries)\n", os.Args[index], float64(time.Since(start))/float64(time.Second), count)
		}
	}
	start := time.Now()
	description := ""
	if index := strings.Index(os.Args[2], "@"); index > 0 {
		description = os.Args[2][index+1:]
		os.Args[2] = os.Args[2][:index]
	}
	if _, err := pfdb.Save(os.Args[2], description); err == nil {
		fmt.Fprintf(os.Stderr, "saved database   [%s] (%.3fs - total[%s] strings[%s] numbers[%s] pairs[%s] clusters[%s] maps[%s] nodes[%s])\n",
			os.Args[2], float64(time.Since(start))/float64(time.Second), size(pfdb.Total), size(pfdb.Strings[0]),
			size(pfdb.Numbers[0]), size(pfdb.Pairs[0]), size(pfdb.Clusters[0]), size(pfdb.Maps[0]), size(pfdb.Nodes[0]),
		)
	} else {
		fmt.Fprintf(os.Stderr, "saving database   [%s] failed (%v)\n", os.Args[2], err)
	}
}

func mkoui() {
	for index := 3; index < len(os.Args); index++ {
		count := 0
		if handle, err := os.Open(os.Args[index]); err == nil {
			reader := bufio.NewReader(handle)
			last := time.Now()
			start := last
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					// TODO 12:34:56:78:9a:bc -> fe80::1034:56ff:fe78:9abc
					data, address, mask := OUI{}, "fe80:0000:0000:0000:0000:", 80
					if json.Unmarshal([]byte(line), &data) == nil {
						if fields := ouiMatcher.FindStringSubmatch(strings.TrimSpace(data.Mac)); len(fields) > 6 {
							for index := 1; index <= 6; index++ {
								if len(fields[index]) != 0 {
									mask += 4 * len(fields[index])
									if len(fields[index]) == 1 {
										fields[index] += "0"
									}
								}
								value, _ := strconv.ParseInt(fields[index], 16, 32)
								address += fmt.Sprintf("%02x", value)
								if index == 2 || index == 4 {
									address += ":"
								}
							}
							if prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", address, mask)); err == nil {
								pfdb.Add(prefix, map[string]any{"company": data.Company}, nil)
								count++
							}
						}
					}
				}
				if now := time.Now(); now.Sub(last) >= 250*time.Millisecond {
					last = now
					fmt.Fprintf(os.Stderr, "\radding prefixes  [%s] %d", os.Args[index], count)
				}
			}
			handle.Close()
			fmt.Fprintf(os.Stderr, "\radded prefixes   [%s] (%.3fs - %d entries)\n", os.Args[index], float64(time.Since(start))/float64(time.Second), count)
		}
	}
	start := time.Now()
	description := ""
	if index := strings.Index(os.Args[2], "@"); index > 0 {
		description = os.Args[2][index+1:]
		os.Args[2] = os.Args[2][:index]
	}
	if _, err := pfdb.Save(os.Args[2], description); err == nil {
		fmt.Fprintf(os.Stderr, "saved database   [%s] (%.3fs - total[%s] strings[%s] numbers[%s] pairs[%s] clusters[%s] maps[%s] nodes[%s])\n",
			os.Args[2], float64(time.Since(start))/float64(time.Second), size(pfdb.Total), size(pfdb.Strings[0]),
			size(pfdb.Numbers[0]), size(pfdb.Pairs[0]), size(pfdb.Clusters[0]), size(pfdb.Maps[0]), size(pfdb.Nodes[0]),
		)
	} else {
		fmt.Fprintf(os.Stderr, "saving database   [%s] failed (%v)\n", os.Args[2], err)
	}
}

func mkcity() {
	locations := map[int]*LOCATION{}
	if handle, err := os.Open(os.Args[3]); err == nil {
		reader := bufio.NewReader(handle)
		last := time.Now()
		start := last
		for {
			if line, err := reader.ReadString('\n'); err != nil {
				break
			} else {
				if fields := csvMatcher.FindAllStringSubmatch(strings.TrimSpace(line), -1); len(fields) == 14 {
					for index := 0; index < len(fields); index++ {
						fields[index][1] = strings.Trim(fields[index][1], `"`)
					}
					if id, err := strconv.Atoi(fields[0][1]); err == nil {
						locations[id] = &LOCATION{
							ContinentCode: fields[2][1],
							ContinentName: fields[3][1],
							CountryCode:   fields[4][1],
							CountryName:   fields[5][1],
							RegionCode:    fields[6][1],
							RegionName:    fields[7][1],
							StateCode:     fields[8][1],
							StateName:     fields[9][1],
							CityName:      fields[10][1],
							TimeZone:      fields[12][1],
							InEurope:      fields[13][1] == "1",
						}
					}
				}
			}
			if now := time.Now(); now.Sub(last) >= 250*time.Millisecond {
				last = now
				fmt.Fprintf(os.Stderr, "\rloading locations [%s] %d", os.Args[3], len(locations))
			}
		}
		handle.Close()
		time.Sleep(time.Millisecond)
		fmt.Fprintf(os.Stderr, "\rloaded locations [%s] (%v - %d entries)\n", os.Args[3], time.Since(start).Truncate(time.Millisecond), len(locations))
	}

	clusters := [][]string{
		[]string{"continent_code", "continent_name", "country_code", "country_name", "region_code", "region_name", "state_code", "state_name", "timezone", "in_europe"},
		[]string{"city_name", "postal_code", "latitude", "longitude"},
	}
	for index := 4; index < len(os.Args); index++ {
		count := 0
		if handle, err := os.Open(os.Args[index]); err == nil {
			reader := bufio.NewReader(handle)
			last := time.Now()
			start := last
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					if fields := strings.Split(strings.TrimSpace(line), ","); len(fields) >= 10 {
						id := 0
						if id, _ = strconv.Atoi(fields[1]); id == 0 {
							id, _ = strconv.Atoi(fields[2])
						}
						if id != 0 && locations[id] != nil {
							if prefix, err := netip.ParsePrefix(fields[0]); err == nil {
								latitude, _ := strconv.ParseFloat(fields[7], 64)
								longitude, _ := strconv.ParseFloat(fields[8], 64)
								pfdb.Add(prefix, map[string]any{
									"continent_code": locations[id].ContinentCode,
									"continent_name": locations[id].ContinentName,
									"country_code":   locations[id].CountryCode,
									"country_name":   locations[id].CountryName,
									"region_code":    locations[id].RegionCode,
									"region_name":    locations[id].RegionName,
									"state_code":     locations[id].StateCode,
									"state_name":     locations[id].StateName,
									"city_name":      locations[id].CityName,
									"in_europe":      locations[id].InEurope,
									"timezone":       locations[id].TimeZone,
									"postal_code":    fields[6],
									"latitude":       latitude,
									"longitude":      longitude,
								}, clusters)
								count++
							}
						}
					}
				}
				if now := time.Now(); now.Sub(last) >= 250*time.Millisecond {
					last = now
					fmt.Fprintf(os.Stderr, "\radding prefixes  [%s] %d", os.Args[index], count)
				}
			}
			handle.Close()
			time.Sleep(time.Millisecond)
			fmt.Fprintf(os.Stderr, "\radded prefixes   [%s] (%v - %d entries)\n", os.Args[index], time.Since(start).Truncate(time.Millisecond), count)
		}
	}

	start := time.Now()
	description := ""
	if index := strings.Index(os.Args[2], "@"); index > 0 {
		description = os.Args[2][index+1:]
		os.Args[2] = os.Args[2][:index]
	}
	if _, err := pfdb.Save(os.Args[2], description); err == nil {
		fmt.Fprintf(os.Stderr, "saved database   [%s] (%.3fs - total[%s] strings[%s] numbers[%s] pairs[%s] clusters[%s] maps[%s] nodes[%s])\n",
			os.Args[2], float64(time.Since(start))/float64(time.Second), size(pfdb.Total), size(pfdb.Strings[0]),
			size(pfdb.Numbers[0]), size(pfdb.Pairs[0]), size(pfdb.Clusters[0]), size(pfdb.Maps[0]), size(pfdb.Nodes[0]),
		)
	} else {
		fmt.Fprintf(os.Stderr, "saving database  [%s] failed (%v)\n", os.Args[2], err)
	}
}

func mkasn() {
	for index := 3; index < len(os.Args); index++ {
		count := 0
		if handle, err := os.Open(os.Args[index]); err == nil {
			reader := bufio.NewReader(handle)
			last := time.Now()
			start := last
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					if fields := csvMatcher.FindAllStringSubmatch(strings.TrimSpace(line), -1); len(fields) == 3 {
						for index := 0; index < len(fields); index++ {
							fields[index][1] = strings.Trim(fields[index][1], `"`)
						}
						if asnum, _ := strconv.Atoi(fields[1][1]); asnum != 0 {
							if prefix, err := netip.ParsePrefix(fields[0][1]); err == nil {
								pfdb.Add(prefix, map[string]any{
									"as_number": fmt.Sprintf("AS%d", asnum),
									"as_name":   fields[2][1],
								}, nil)
								count++
							}
						}
					}
				}
				if now := time.Now(); now.Sub(last) >= 250*time.Millisecond {
					last = now
					fmt.Fprintf(os.Stderr, "\radding prefixes   [%s] %d", os.Args[index], count)
				}
			}
			handle.Close()
			time.Sleep(time.Millisecond)
			fmt.Fprintf(os.Stderr, "\radded prefixes   [%s] (%v - %d entries)\n", os.Args[index], time.Since(start).Truncate(time.Millisecond), count)
		}
	}

	start := time.Now()
	description := ""
	if index := strings.Index(os.Args[2], "@"); index > 0 {
		description = os.Args[2][index+1:]
		os.Args[2] = os.Args[2][:index]
	}
	if _, err := pfdb.Save(os.Args[2], description); err == nil {
		fmt.Fprintf(os.Stderr, "saved database   [%s] (%.3fs - total[%s] strings[%s] numbers[%s] pairs[%s] clusters[%s] maps[%s] nodes[%s])\n",
			os.Args[2], float64(time.Since(start))/float64(time.Second), size(pfdb.Total), size(pfdb.Strings[0]),
			size(pfdb.Numbers[0]), size(pfdb.Pairs[0]), size(pfdb.Clusters[0]), size(pfdb.Maps[0]), size(pfdb.Nodes[0]),
		)
	} else {
		fmt.Fprintf(os.Stderr, "saving database  [%s] failed (%v)\n", os.Args[2], err)
	}
}

func rlookup(remote, value string, out map[string]any) {
	if remote != "" && value != "" && out != nil {
		if request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?remote=%s", remote, value), nil); err == nil {
			request.Header.Add("X-Forwarded-For", value)
			if response, err := client.Do(request); err == nil {
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				data := map[string]any{}
				json.Unmarshal(body, &data)
				for key, value := range data {
					if _, ok := out[key]; !ok {
						out[key] = value
					}
				}
			}
		}
	}
}

func lookup() {
	databases, remote := []*prefixdb.PrefixDB{}, ""
	for index := 2; index < len(os.Args); index++ {
		if strings.HasSuffix(os.Args[index], `.pfdb`) {
			database := prefixdb.New()
			if err := database.Load(os.Args[index]); err == nil {
				fmt.Fprintf(os.Stderr, "database [%s] (total[%s] version[%d.%d.%d] description[%s])\n",
					os.Args[index], size(database.Total), (database.Version>>16)&0xff, (database.Version>>8)&0xff, database.Version&0xff, database.Description)
				databases = append(databases, database)
			} else {
				fmt.Fprintf(os.Stderr, "database [%s] failed (%v)\n", os.Args[index], err)
			}
		} else if strings.HasPrefix(os.Args[index], `http`) {
			lookup := map[string]any{}
			if rlookup(os.Args[index], "8.8.8.8", lookup); len(lookup) != 0 {
				remote = os.Args[index]
				fmt.Fprintf(os.Stderr, "remote   [%s]\n", os.Args[index])
			} else {
				fmt.Fprintf(os.Stderr, "remote   [%s] failed (not a valid prefixdb server)\n", os.Args[index])
			}
		} else {
			fmt.Fprintf(os.Stderr, "lookup   [%s] ", os.Args[index])
			lookup := map[string]any{}
			for _, database := range databases {
				database.Lookup(os.Args[index], lookup)
			}
			if remote != "" {
				rlookup(remote, os.Args[index], lookup)
			}
			data, _ := json.Marshal(lookup)
			fmt.Printf("%s\n", data)
		}
	}
}

func batch() {
	databases, remote := []*prefixdb.PrefixDB{}, ""
	for index := 2; index < len(os.Args); index++ {
		if strings.HasSuffix(os.Args[index], `.pfdb`) {
			database := prefixdb.New()
			if err := database.Load(os.Args[index]); err == nil {
				fmt.Fprintf(os.Stderr, "database [%s] (total[%s] version[%d.%d.%d] description[%s])\n",
					os.Args[index], size(database.Total), (database.Version>>16)&0xff, (database.Version>>8)&0xff, database.Version&0xff, database.Description)
				databases = append(databases, database)
			} else {
				fmt.Fprintf(os.Stderr, "database [%s] failed (%v)\n", os.Args[index], err)
			}
		} else if strings.HasPrefix(os.Args[index], `http`) {
			lookup := map[string]any{}
			if rlookup(os.Args[index], "8.8.8.8", lookup); len(lookup) != 0 {
				remote = os.Args[index]
				fmt.Fprintf(os.Stderr, "remote   [%s]\n", os.Args[index])
			} else {
				fmt.Fprintf(os.Stderr, "remote   [%s] failed (not a valid prefixdb server)\n", os.Args[index])
			}
		} else {
			in, column, parts := os.Stdin, 1, strings.Split(os.Args[index], "@")
			if parts[0] == "" {
				usage(1)
			}
			if len(parts) > 1 {
				column, _ = strconv.Atoi(parts[1])
			}
			if parts[0] != "-" {
				in, _ = os.Open(parts[0])
			}
			reader, writer, cache := csv.NewReader(in), csv.NewWriter(os.Stdout), map[string]map[string]any{}
			if records, err := reader.ReadAll(); err == nil {
				column = max(1, min(reader.FieldsPerRecord, column)) - 1
				for done, record := range records {
					if len(record) > column {
						lookup := map[string]any{}
						if _, ok := cache[record[column]]; ok {
							lookup = cache[record[column]]
						} else {
							for _, database := range databases {
								database.Lookup(record[column], lookup)
							}
							if remote != "" {
								rlookup(remote, record[column], lookup)
							}
							cache[record[column]] = lookup
						}
						for field := index + 1; field < len(os.Args); field++ {
							if lookup[os.Args[field]] != nil {
								record = append(record, fmt.Sprintf("%v", lookup[os.Args[field]]))
							} else {
								record = append(record, "")
							}

						}
					}
					fmt.Fprintf(os.Stderr, "\rlookup   [%s] (%d/%d)                                        \r", record[column], done+1, len(records))
					writer.Write(record)
					writer.Flush()
				}
				fmt.Fprintf(os.Stderr, "\rlookup   [%d records]                                        \n", len(records))
			} else {
				fmt.Fprintf(os.Stderr, "csv      [%s] failed (%v)\n", os.Args[index], err)
			}
			break
		}
	}
}

func server() {
	databases := []*prefixdb.PrefixDB{}
	for index := 3; index < len(os.Args); index++ {
		database := prefixdb.New()
		if err := database.Load(os.Args[index]); err == nil {
			fmt.Fprintf(os.Stderr, "database [%s] (total[%s] version[%d.%d.%d] description[%s])\n",
				os.Args[index], size(database.Total), (database.Version>>16)&0xff, (database.Version>>8)&0xff, database.Version&0xff, database.Description)
			databases = append(databases, database)
		} else {
			fmt.Fprintf(os.Stderr, "database [%s] failed (%v)\n", os.Args[index], err)
		}
	}
	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Access-Control-Allow-Origin", "*")
		remote := request.RemoteAddr
		if value, err := netip.ParseAddrPort(remote); err == nil {
			remote = value.Addr().String()
		}
		if value := request.Header.Get("X-Forwarded-For"); value != "" {
			remote = strings.Split(value, ",")[0]
		}
		parameters := request.URL.Query()
		if value := parameters.Get("remote"); value != "" {
			remote = value
		}
		lookup := map[string]any{"ip": remote}
		for _, database := range databases {
			database.Lookup(remote, lookup)
		}
		data, _ := json.Marshal(lookup)
		response.Write(data)
		fmt.Fprintf(os.Stderr, "lookup   [%s] %s\n", remote, data)
	})
	parts := strings.Split(os.Args[2], ",")
	server := &http.Server{
		Addr:           strings.TrimLeft(parts[0], "*"),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 4 << 10,
	}
	fmt.Fprintf(os.Stderr, "listen   [%s]\n", os.Args[2])
	for {
		if len(parts) > 1 {
			if err := server.ListenAndServeTLS(parts[1], parts[2]); err != nil {
				fmt.Fprintf(os.Stderr, "listen   [%s] failed (%v)\n", os.Args[2], err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil {
				fmt.Fprintf(os.Stderr, "listen   [%s] failed (%v)\n", os.Args[2], err)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func usage(status int) {
	fmt.Fprintf(os.Stderr, "usage: prefixdb <action> [parameters...]\n\n"+
		"help                                                                  show this help screen\n"+
		"json   <database[@<description>]> <JSON prefixes>...                  build database from generic JSON-formatted prefixes lists\n"+
		"oui    <database[@<description>]> <JSON OUI>...                       build database from macadress.io JSON OUI lists\n"+
		"city   <database[@<description>]> <CSV locations> <CSV prefixes>...   build database from MaxMind GeoIP2 cities lists\n"+
		"asn    <database[@<description>]> <CSV prefixes>...                   build database from MaxMind GeoLite2 asnums lists\n"+
		"lookup <database|url>... <address>...                                 lookup entries in database (or from remote server url)\n"+
		"batch  <database|url>... <CSV input|->[@<column>] <field>...          batch-lookup entries in input CSV file (or stdin)\n"+
		"server <listen> <database>...                                         spawn an HTTP(S) server for remote lookup\n")
	os.Exit(status)
}

func main() {
	if len(os.Args) < 2 {
		usage(1)
	}
	switch os.Args[1] {
	case "help":
		usage(0)

	case "json":
		if len(os.Args) < 3 {
			usage(1)
		}
		mkjson()

	case "oui":
		if len(os.Args) < 3 {
			usage(1)
		}
		mkoui()

	case "city":
		if len(os.Args) < 5 {
			usage(1)
		}
		mkcity()

	case "asn":
		if len(os.Args) < 3 {
			usage(1)
		}
		mkasn()

	case "lookup":
		lookup()

	case "batch":
		batch()

	case "server":
		if len(os.Args) < 3 {
			usage(1)
		}
		server()

	default:
		usage(2)
	}
}
