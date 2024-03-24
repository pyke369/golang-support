package whohas

import (
	"context"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BACKEND struct {
	Host    string
	Secure  bool
	Path    string
	Headers map[string]string
	Penalty time.Duration
	Probe   bool
}
type CACHE struct {
	TTL   time.Duration
	last  time.Time
	items map[string]*LOOKUP
	sync.RWMutex
}
type LOOKUP struct {
	index    int
	deadline time.Time
	Protocol string
	Host     string
	Headers  map[string]string
	Size     int64
	Mime     string
	Ranges   bool
	Date     time.Time
	Modified time.Time
	Expires  time.Time
}

var (
	matcher = regexp.MustCompile(`^bytes \d+-\d+/(\d+)$`)
)

func Lookup(path string, backends []BACKEND, timeout time.Duration, cache *CACHE, ckey string) (lookup *LOOKUP) {
	if path == "" || backends == nil || len(backends) < 1 || timeout < 100*time.Millisecond {
		return
	}

	cpath := path
	if index := strings.Index(path, "?"); index >= 0 {
		cpath = path[:index]
	}
	cbackends := backends
	if cache != nil && cache.items != nil {
		now := time.Now()
		cache.RLock()
		if cache.items[cpath] != nil && now.Sub(cache.items[cpath].deadline) < 0 {
			lookup = cache.items[cpath]
			if cache.items[cpath].Host != "" {
				cbackends = []BACKEND{}
				for _, backend := range backends {
					if backend.Host == cache.items[cpath].Host {
						cbackends = append(cbackends, backend)
						break
					}
				}
				if len(cbackends) < 1 {
					cbackends = backends
				}
			}
		}
		if len(cbackends) == len(backends) && ckey != "" && cache.items["k"+ckey] != nil && now.Sub(cache.items["k"+ckey].deadline) < 0 {
			cbackends = []BACKEND{}
			for _, backend := range backends {
				if backend.Host == cache.items["k"+ckey].Host {
					cbackends = append(cbackends, backend)
					break
				}
			}
			if len(cbackends) < 1 {
				cbackends = backends
			}
		}
		cache.RUnlock()
	}

	if lookup == nil {
		inflight := len(cbackends)
		sink := make(chan LOOKUP, inflight+1)
		cancels := make([]context.CancelFunc, inflight)
		for index, backend := range cbackends {
			var ctx context.Context

			ctx, cancels[index] = context.WithCancel(context.Background())
			go func(index int, backend BACKEND, ctx context.Context) {
				lookup := LOOKUP{index: index}
				if backend.Penalty != 0 && len(cbackends) > 1 {
					select {
					case <-time.After(backend.Penalty):
					case <-ctx.Done():
						sink <- lookup
						return
					}
				}
				method := http.MethodHead
				if backend.Probe {
					method = http.MethodGet
				}
				lookup.Protocol = "http"
				if backend.Secure {
					lookup.Protocol = "https"
				}
				rpath := path
				if backend.Path != "" {
					rpath = backend.Path
				}
				if request, err := http.NewRequest(method, lookup.Protocol+"://"+backend.Host+rpath, nil); err == nil {
					request = request.WithContext(ctx)
					request.Header.Set("User-Agent", "whohas")
					if backend.Probe {
						request.Header.Set("Range", "bytes=0-1")
					}
					if backend.Headers != nil {
						lookup.Headers = map[string]string{}
						for name, value := range backend.Headers {
							lookup.Headers[name] = value
							request.Header.Set(name, value)
						}
					}

					if response, err := http.DefaultClient.Do(request); err == nil {
						if response.StatusCode/100 == 2 {
							lookup.Host = backend.Host
							lookup.Size, _ = strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
							if crange := response.Header.Get("Content-Range"); crange != "" {
								if captures := matcher.FindStringSubmatch(crange); captures != nil {
									lookup.Size, _ = strconv.ParseInt(captures[1], 10, 64)
								}
							}
							lookup.Mime = response.Header.Get("Content-Type")
							if lookup.Mime == "" || lookup.Mime == "application/octet-stream" || lookup.Mime == "text/plain" {
								if extension := filepath.Ext(path); extension != "" {
									lookup.Mime = mime.TypeByExtension(extension)
								}
							}
							if response.Header.Get("Accept-Ranges") != "" || response.StatusCode == 206 {
								lookup.Ranges = true
							}
							if header := response.Header.Get("Date"); header != "" {
								lookup.Date, _ = http.ParseTime(header)
							} else {
								lookup.Date = time.Now()
							}
							if header := response.Header.Get("Last-Modified"); header != "" {
								lookup.Modified, _ = http.ParseTime(header)
							}
							if header := response.Header.Get("Expires"); header != "" {
								lookup.Expires, _ = http.ParseTime(header)
							} else {
								lookup.Expires = lookup.Date.Add(time.Hour)
							}
							if lookup.Expires.Sub(lookup.Date) < 2*time.Second {
								lookup.Expires = lookup.Date.Add(2 * time.Second)
							}
						}
						response.Body.Close()
					}
				}
				sink <- lookup
			}(index, backend, ctx)
		}

		for inflight > 0 {
			select {
			case result := <-sink:
				inflight--
				cancels[result.index] = nil
				if result.Host != "" {
					lookup = &result
					for index, cancel := range cancels {
						if cancels[index] != nil && index != result.index {
							cancel()
							cancels[index] = nil
						}
					}
				}
			case <-time.After(timeout):
				for index, cancel := range cancels {
					if cancels[index] != nil {
						cancel()
					}
				}
			}
		}
		close(sink)
	}

	if cache != nil {
		now := time.Now()
		cache.Lock()
		if cache.items == nil {
			cache.items = map[string]*LOOKUP{}
		}
		if now.Sub(cache.last) >= 5*time.Second {
			cache.last = now
			for key, item := range cache.items {
				if now.Sub(item.deadline) >= 0 {
					delete(cache.items, key)
				}
			}
		}
		if lookup == nil || lookup.Host == "" {
			if ckey != "" {
				delete(cache.items, "k"+ckey)
			}
			if cache.items[cpath] == nil {
				cache.items[cpath] = &LOOKUP{deadline: now.Add(5 * time.Second)}
			}
			lookup = nil
		} else {
			cache.TTL = max(cache.TTL, 2*time.Second)
			if ckey != "" {
				cache.items["k"+ckey] = &LOOKUP{Host: lookup.Host, deadline: now.Add(cache.TTL)}
			}
			if cache.items[cpath] == nil {
				lookup.deadline = now.Add(min(min(max(lookup.Expires.Sub(lookup.Date), 2*time.Second), cache.TTL), 10*time.Minute))
				cache.items[cpath] = lookup
			}
		}
		cache.Unlock()
	}

	return
}

func Evict(path string, cache *CACHE, ckey string) {
	if path != "" && cache != nil && cache.items != nil {
		cpath := path
		if index := strings.Index(path, "?"); index >= 0 {
			cpath = path[:index]
		}
		cache.Lock()
		delete(cache.items, cpath)
		if ckey != "" {
			delete(cache.items, "k"+ckey)
		}
		cache.Unlock()
	}
}
