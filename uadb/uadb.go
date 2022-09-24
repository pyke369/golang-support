package uadb

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pyke369/golang-support/rcache"
)

type cache struct {
	value map[string]string
	last  int
}

type UADB struct {
	Version  string               `json:"version"`
	Agents   [][8]string          `json:"agents"`   // [ match_expr, ua_family, ua_company, ua_type, device_type, os_family, os_name, os_company ]
	Devices  [][2]string          `json:"devices"`  // [ match_expr, device_type ]
	Systems  [][4]string          `json:"systems"`  // [ match_expr, os_family, os_name, os_company ]
	Crawlers map[string][5]string `json:"crawlers"` // user-agent -> [ ua_family, ua_name, ua_company, ua_version, ua_type ]
	lock     sync.RWMutex
	cache    map[string]*cache
	last     time.Time
	max      int
	hit      int64
	miss     int64
}

var fields = []string{"ua_family", "ua_name", "ua_company", "ua_type", "ua_version", "os_family", "os_name", "os_company", "device_type"}

func tocode(input string) string {
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
								input,
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
	max := 250000
	if len(size) > 0 && size[0] >= 1000 && size[0] <= 500000 {
		max = size[0]
	}
	return &UADB{Crawlers: map[string][5]string{}, cache: map[string]*cache{}, max: max}
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
			return fmt.Errorf("invalid uadb database")
		}
		db.Version, db.Agents, db.Devices, db.Systems, db.Crawlers = loaded.Version, loaded.Agents, loaded.Devices, loaded.Systems, loaded.Crawlers
		db.lock.Lock()
		db.cache = map[string]*cache{}
		db.lock.Unlock()
	}

	return nil
}

func (db *UADB) Lookup(ua string, withcode ...bool) (output map[string]string) {

	ckey := fmt.Sprintf("%x", md5.Sum([]byte(ua)))
	db.lock.RLock()
	if cache := db.cache[ckey]; cache != nil {
		output = cache.value
		cache.last = int(time.Now().Unix())
		atomic.AddInt64(&(db.hit), 1)
	}
	db.lock.RUnlock()

	if output == nil {
		atomic.AddInt64(&(db.miss), 1)
		output = map[string]string{}
		for _, field := range fields {
			output[field] = "unknown"
		}
		if db.Version == "" || len(db.Agents) == 0 || len(db.Devices) == 0 || len(db.Systems) == 0 || len(db.Crawlers) == 0 {
			return
		}

		if crawler := db.Crawlers[ua]; crawler[0] != "" {
			output["ua_family"], output["ua_type"] = crawler[0], "Crawler"
			if crawler[1] != "" {
				output["ua_name"] = crawler[1]
			}
			if crawler[2] != "" {
				output["ua_company"] = crawler[2]
			}
			if crawler[3] != "" {
				output["ua_version"] = crawler[3]
			}
			if crawler[4] != "" {
				output["device_type"] = crawler[4]
			}
		} else {
			for _, agent := range db.Agents {
				if matcher := rcache.Get(agent[0]); matcher != nil && matcher.MatchString(ua) {
					if agent[1] != "" {
						output["ua_family"], output["ua_name"] = agent[1], agent[1]
						if matches := matcher.FindStringSubmatch(ua); len(matches) > 1 {
							output["ua_version"] = matches[1]
							output["ua_name"] += " " + matches[1]
						}
					}
					if agent[2] != "" {
						output["ua_company"] = agent[2]
					}
					if agent[3] != "" {
						output["ua_type"] = agent[3]
					}
					if agent[4] != "" {
						output["device_type"] = agent[4]
					}
					if agent[5] != "" {
						output["os_family"] = agent[5]
					}
					if agent[6] != "" {
						output["os_name"] = agent[6]
					}
					if agent[7] != "" {
						output["os_company"] = agent[7]
					}
					break
				}
			}

			if output["ua_family"] != "unknown" {
				if output["device_type"] == "unknown" {
					for _, device := range db.Devices {
						if matcher := rcache.Get(device[0]); matcher != nil && matcher.MatchString(ua) {
							if device[1] != "" {
								output["device_type"] = device[1]
							}
							break
						}
					}
					if output["device_type"] == "unknown" {
						ua_type := tocode(output["ua_type"])
						if ua_type == "mobile_browser" || ua_type == "wap_browser" {
							output["device_type"] = "Smartphone"
						} else if ua_type == "library" || ua_type == "validator" || ua_type == "unrecognized" || ua_type == "useragent_anonymizer" {
							output["device_type"] = "Other"
						} else {
							output["device_type"] = "Personal computer"
						}
					}
				}

				if output["os_family"] == "unknown" {
					for _, system := range db.Systems {
						if matcher := rcache.Get(system[0]); matcher != nil && matcher.MatchString(ua) {
							if system[1] != "" {
								output["os_family"] = system[1]
							}
							if system[2] != "" {
								output["os_name"] = system[2]
							}
							if system[3] != "" {
								output["os_company"] = system[3]
							}
							break
						}
					}
				}
			}
		}

		db.lock.Lock()
		db.cache[ckey] = &cache{value: output, last: int(time.Now().Unix())}
		max := int(float64(db.max) * 1.2)
		if len(db.cache) >= max && time.Since(db.last) >= 15*time.Second {
			db.last = time.Now()
			sorter := []string{}
			for key, value := range db.cache {
				sorter = append(sorter, fmt.Sprintf("%d@@%s", value.last, key))
			}
			sort.Strings(sorter)
			for index := 0; index < len(sorter)-db.max; index++ {
				parts := strings.Split(sorter[index], "@@")
				delete(db.cache, parts[1])
			}
		}
		db.lock.Unlock()
	}

	if len(withcode) > 0 && withcode[0] {
		coutput := map[string]string{}
		for _, field := range fields {
			coutput[field] = output[field]
			if field != "ua_name" && field != "ua_version" && field != "os_version" {
				coutput[field+"_code"] = tocode(output[field])
			}
		}
		output = coutput
	}

	return
}

func (db *UADB) Stats() (int, int64, int64) {
	db.lock.RLock()
	defer db.lock.RUnlock()
	return len(db.cache), atomic.LoadInt64(&(db.hit)), atomic.LoadInt64(&(db.miss))
}
