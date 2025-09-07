package uadb

import (
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pyke369/golang-support/rcache"
)

type cache struct {
	values map[string]string
	last   int
}

type UADB struct {
	Version  string               `json:"version"`
	Agents   [][8]string          `json:"agents"`   // [ match_expr, ua_family, ua_company, ua_type, device_type, os_family, os_name, os_company ]
	Devices  [][2]string          `json:"devices"`  // [ match_expr, device_type ]
	Systems  [][4]string          `json:"systems"`  // [ match_expr, os_family, os_name, os_company ]
	Crawlers map[string][5]string `json:"crawlers"` // user-agent -> [ ua_family, ua_name, ua_company, ua_version, ua_type ]
	lock     sync.RWMutex
	cache    map[uint32]*cache
	last     time.Time
	highest  int
}

var fields = []string{"ua_family", "ua_name", "ua_company", "ua_type", "ua_version", "os_family", "os_name", "os_company", "device_type"}

func tocode(in string) string {
	const removed = "@[]^_`!\"#$%&'()*+,-/:;<=>?{|}~"

	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.TrimSpace(
				strings.ReplaceAll(
					strings.ToLower(
						strings.Map(func(r rune) rune {
							if strings.ContainsRune(removed, r) {
								return -1
							}
							return r
						},
							strings.Trim(
								in,
								".",
							),
						),
					),
					".", " ",
				),
			),
			"  ", " ",
		),
		" ", "_",
	)
}

func New(size ...int) *UADB {
	highest := 1000000
	if len(size) > 0 && size[0] >= 1000 && size[0] <= 1000000 {
		highest = size[0]
	}
	return &UADB{Crawlers: map[string][5]string{}, cache: map[uint32]*cache{}, highest: highest}
}

func (db *UADB) Load(path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	loaded := New()
	if err := json.Unmarshal(payload, loaded); err != nil {
		return err
	}
	if loaded.Version == "" || len(loaded.Agents) == 0 || len(loaded.Devices) == 0 || len(loaded.Systems) == 0 || len(loaded.Crawlers) == 0 {
		return errors.New("invalid uadb database")
	}
	db.Version, db.Agents, db.Devices, db.Systems, db.Crawlers = loaded.Version, loaded.Agents, loaded.Devices, loaded.Systems, loaded.Crawlers
	db.lock.Lock()
	db.cache = map[uint32]*cache{}
	db.lock.Unlock()

	return nil
}

func (db *UADB) Lookup(ua string, out map[string]string, withcode ...bool) {
	if out == nil {
		return
	}

	ckey, wantcode := crc32.ChecksumIEEE(unsafe.Slice(unsafe.StringData(ua), len(ua))), len(withcode) > 0 && withcode[0]
	db.lock.RLock()
	if cache := db.cache[ckey]; cache != nil {
		for key, value := range cache.values {
			if wantcode || (!wantcode && !strings.HasSuffix(key, "_code")) {
				out[key] = value
			}
		}
		cache.last = int(time.Now().Unix())
	}
	db.lock.RUnlock()
	if len(out) > 0 {
		return
	}

	for _, field := range fields {
		out[field] = "unknown"
		if wantcode {
			if field != "ua_name" && field != "ua_version" && field != "os_version" {
				out[field+"_code"] = "unknown"
			}
		}
	}
	if db.Version == "" || len(db.Agents) == 0 || len(db.Devices) == 0 || len(db.Systems) == 0 || len(db.Crawlers) == 0 {
		return
	}

	if crawler := db.Crawlers[ua]; crawler[0] != "" {
		out["ua_family"], out["ua_type"] = crawler[0], "Crawler"
		if crawler[1] != "" {
			out["ua_name"] = crawler[1]
		}
		if crawler[2] != "" {
			out["ua_company"] = crawler[2]
		}
		if crawler[3] != "" {
			out["ua_version"] = crawler[3]
		}
		if crawler[4] != "" {
			out["device_type"] = crawler[4]
		}

	} else {
		for index := 0; index < len(db.Agents); index++ {
			matcher := rcache.Get(db.Agents[index][0])
			if !matcher.MatchString(ua) {
				continue
			}
			if db.Agents[index][1] != "" {
				out["ua_family"], out["ua_name"] = db.Agents[index][1], db.Agents[index][1]
				if captures := matcher.FindStringSubmatch(ua); len(captures) > 1 {
					out["ua_version"] = captures[1]
					out["ua_name"] += " " + captures[1]
				}
			}
			if db.Agents[index][2] != "" {
				out["ua_company"] = db.Agents[index][2]
			}
			if db.Agents[index][3] != "" {
				out["ua_type"] = db.Agents[index][3]
			}
			if db.Agents[index][4] != "" {
				out["device_type"] = db.Agents[index][4]
			}
			if db.Agents[index][5] != "" {
				out["os_family"] = db.Agents[index][5]
			}
			if db.Agents[index][6] != "" {
				out["os_name"] = db.Agents[index][6]
			}
			if db.Agents[index][7] != "" {
				out["os_company"] = db.Agents[index][7]
			}
			break
		}

		if out["ua_family"] != "unknown" {
			if out["device_type"] == "unknown" {
				for _, device := range db.Devices {
					if rcache.Get(device[0]).MatchString(ua) {
						if device[1] != "" {
							out["device_type"] = device[1]
						}
						break
					}
				}
				if out["device_type"] == "unknown" {
					ua_type := tocode(out["ua_type"])
					switch ua_type {
					case "mobile_browser", "wap_browser":
						out["device_type"] = "Smartphone"

					case "library", "validator", "unrecognized", "useragent_anonymizer":
						out["device_type"] = "Other"

					default:
						out["device_type"] = "Personal computer"
					}
				}
			}

			if out["os_family"] == "unknown" {
				for _, system := range db.Systems {
					if rcache.Get(system[0]).MatchString(ua) {
						if system[1] != "" {
							out["os_family"] = system[1]
						}
						if system[2] != "" {
							out["os_name"] = system[2]
						}
						if system[3] != "" {
							out["os_company"] = system[3]
						}
						break
					}
				}
			}
		}
	}

	values := map[string]string{}
	for key, value := range out {
		values[key] = value
	}
	for _, field := range fields {
		if field != "ua_name" && field != "ua_version" && field != "os_version" {
			values[field+"_code"] = tocode(values[field])
			if wantcode {
				out[field+"_code"] = values[field+"_code"]
			}
		}
	}
	db.lock.Lock()
	db.cache[ckey] = &cache{values: values, last: int(time.Now().Unix())}
	highest := int(float64(db.highest) * 1.2)
	if len(db.cache) >= highest && time.Since(db.last) >= 15*time.Second {
		db.last = time.Now()
		sorter := []string{}
		for key, value := range db.cache {
			sorter = append(sorter, strconv.Itoa(value.last)+"@@"+strconv.Itoa(int(key)))
		}
		sort.Strings(sorter)
		for index := 0; index < len(sorter)-db.highest; index++ {
			key, _ := strconv.ParseUint(strings.Split(sorter[index], "@@")[1], 10, 32)
			delete(db.cache, uint32(key))
		}
	}
	db.lock.Unlock()
}
