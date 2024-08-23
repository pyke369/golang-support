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
	"sync/atomic"
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
	hit      int64
	miss     int64
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
	if payload, err := os.ReadFile(path); err != nil {
		return err
	} else {
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
	}

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
		atomic.AddInt64(&(db.hit), 1)
	}
	db.lock.RUnlock()
	if len(out) > 0 {
		return
	}

	atomic.AddInt64(&(db.miss), 1)
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
		for _, agent := range db.Agents {
			if matcher := rcache.Get(agent[0]); matcher != nil && matcher.MatchString(ua) {
				if agent[1] != "" {
					out["ua_family"], out["ua_name"] = agent[1], agent[1]
					if matches := matcher.FindStringSubmatch(ua); len(matches) > 1 {
						out["ua_version"] = matches[1]
						out["ua_name"] += " " + matches[1]
					}
				}
				if agent[2] != "" {
					out["ua_company"] = agent[2]
				}
				if agent[3] != "" {
					out["ua_type"] = agent[3]
				}
				if agent[4] != "" {
					out["device_type"] = agent[4]
				}
				if agent[5] != "" {
					out["os_family"] = agent[5]
				}
				if agent[6] != "" {
					out["os_name"] = agent[6]
				}
				if agent[7] != "" {
					out["os_company"] = agent[7]
				}
				break
			}
		}

		if out["ua_family"] != "unknown" {
			if out["device_type"] == "unknown" {
				for _, device := range db.Devices {
					if matcher := rcache.Get(device[0]); matcher != nil && matcher.MatchString(ua) {
						if device[1] != "" {
							out["device_type"] = device[1]
						}
						break
					}
				}
				if out["device_type"] == "unknown" {
					ua_type := tocode(out["ua_type"])
					if ua_type == "mobile_browser" || ua_type == "wap_browser" {
						out["device_type"] = "Smartphone"
					} else if ua_type == "library" || ua_type == "validator" || ua_type == "unrecognized" || ua_type == "useragent_anonymizer" {
						out["device_type"] = "Other"
					} else {
						out["device_type"] = "Personal computer"
					}
				}
			}

			if out["os_family"] == "unknown" {
				for _, system := range db.Systems {
					if matcher := rcache.Get(system[0]); matcher != nil && matcher.MatchString(ua) {
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

func (db *UADB) Stats() (size int, hit, miss int64) {
	db.lock.RLock()
	defer db.lock.RUnlock()
	return len(db.cache), atomic.LoadInt64(&(db.hit)), atomic.LoadInt64(&(db.miss))
}
