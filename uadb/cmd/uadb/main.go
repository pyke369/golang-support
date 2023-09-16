package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uadb"
)

func build() {
	rewriter, target := rcache.Get(`^/(.+)/([gims]*)$`), uadb.New()

	if source, err := sql.Open("sqlite3", os.Args[3]); err == nil {
		if row := source.QueryRow("select version from udger_db_info"); row != nil {
			if row.Scan(&target.Version) == nil && target.Version != "" {
				fmt.Fprintf(os.Stderr, "- opened source database %s (version %s)\n", os.Args[3], target.Version)

				if rows, err := source.Query("select UCR.regstring, UCL.name, UCL.vendor, UCC.client_classification, UDCL.name, UOL.family, UOL.name, UOL.vendor " +
					"from udger_client_regex UCR " +
					"left outer join udger_client_list UCL on (UCL.id = UCR.client_id) " +
					"left outer join udger_client_class UCC on (UCC.id = UCL.class_id) " +
					"left outer join udger_deviceclass_list UDCL on (UDCL.id = UCC.deviceclass_id) " +
					"left outer join udger_client_os_relation UCOR on (UCOR.client_id = UCR.client_id) " +
					"left outer join udger_os_list UOL on (UOL.id = UCOR.os_id) " +
					"order by UCR.sequence asc"); err == nil {
					for rows.Next() {
						agent := [8]string{}
						rows.Scan(&agent[0], &agent[1], &agent[2], &agent[3], &agent[4], &agent[5], &agent[6], &agent[7])
						if agent[0] != "" {
							agent[0] = strings.ReplaceAll(rewriter.ReplaceAllString(agent[0], "(?$2)$1"), `\/`, `/`)
							if rcache.Get(agent[0]) != nil {
								target.Agents = append(target.Agents, agent)
							}
						}
					}
					rows.Close()
				}
				fmt.Fprintf(os.Stderr, "- loaded %d user-agent(s)\n", len(target.Agents))

				if rows, err := source.Query("select UDCR.regstring, UDCL.name " +
					"from udger_deviceclass_regex UDCR " +
					"left outer join udger_deviceclass_list UDCL on (UDCL.id = UDCR.deviceclass_id) " +
					"order by UDCR.sequence asc"); err == nil {
					for rows.Next() {
						device := [2]string{}
						rows.Scan(&device[0], &device[1])
						if device[0] != "" {
							device[0] = strings.ReplaceAll(rewriter.ReplaceAllString(device[0], "(?$2)$1"), `\/`, `/`)
							if rcache.Get(device[0]) != nil {
								target.Devices = append(target.Devices, device)
							}
						}
					}
					rows.Close()
				}
				fmt.Fprintf(os.Stderr, "- loaded %d device(s)\n", len(target.Devices))

				if rows, err := source.Query("select UOR.regstring, UOL.family, UOL.name, UOL.vendor " +
					"from udger_os_regex UOR " +
					"left outer join udger_os_list UOL on (UOL.id = UOR.os_id) " +
					"order by UOR.sequence asc"); err == nil {
					for rows.Next() {
						system := [4]string{}
						rows.Scan(&system[0], &system[1], &system[2], &system[3])
						if system[0] != "" {
							system[0] = strings.ReplaceAll(rewriter.ReplaceAllString(system[0], "(?$2)$1"), `\/`, `/`)
							if rcache.Get(system[0]) != nil {
								target.Systems = append(target.Systems, system)
							}
						}
					}
					rows.Close()
				}
				fmt.Fprintf(os.Stderr, "- loaded %d operating system(s)\n", len(target.Systems))

				if rows, err := source.Query("select UCL.ua_string, UCL.family, UCL.name, UCL.vendor, UCL.ver, UCC.crawler_classification " +
					"from udger_crawler_list UCL " +
					"left outer join udger_crawler_class UCC on (UCC.id = UCL.class_id)"); err == nil {
					for rows.Next() {
						value, crawler := "", [5]string{}
						rows.Scan(&value, &crawler[0], &crawler[1], &crawler[2], &crawler[3], &crawler[4])
						if value != "" {
							target.Crawlers[value] = crawler
						}
					}
					rows.Close()
				}
				fmt.Fprintf(os.Stderr, "- loaded %d crawler(s)\n", len(target.Crawlers))

				if payload, err := json.Marshal(target); err == nil {
					if os.WriteFile(os.Args[2], payload, 0644) == nil {
						fmt.Fprintf(os.Stderr, "- saved target database %s (%d bytes)\n", os.Args[2], len(payload))
					}
				}
			}
		}
	}
}

func lookup() {
	db := uadb.New()
	if err := db.Load(os.Args[2]); err != nil {
		fmt.Printf("%v - exiting\n", err)
		return
	}
	fmt.Printf("- loaded database version %s\n", db.Version)
	for _, agent := range os.Args[3:] {
		fmt.Printf("- %s\n", agent)
		lookup, keys := make(map[string]string, 24), []string{}
		db.Lookup(agent, lookup, true)
		for key := range lookup {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Printf("  %-20.20s  %s\n", key, lookup[key])
		}
	}
}

func bench() {
	db, concurrency := uadb.New(), runtime.NumCPU()*2
	if err := db.Load(os.Args[2]); err != nil {
		fmt.Printf("%v - exiting\n", err)
		return
	}
	fmt.Printf("- loaded database (version %s)\n", db.Version)

	for {
		for round := 1; round <= 5; round++ {
			total, found, start := int32(0), int32(0), time.Now()
			if agents, err := os.ReadFile(os.Args[3]); err == nil {
				queue, waiter := make(chan string, concurrency), sync.WaitGroup{}
				for index := 1; index <= concurrency; index++ {
					waiter.Add(1)
					go func() {
						for {
							if agent := <-queue; agent != "" {
								lookup := make(map[string]string, 24)
								db.Lookup(agent, lookup, false)
								if lookup["ua_family"] != "unknown" {
									atomic.AddInt32(&found, 1)
								}
								continue
							}
							break
						}
						waiter.Done()
					}()
				}
				for _, agent := range strings.Split(string(agents), "\n") {
					if agent != "" {
						queue <- agent
						total++
						if total%99 == 0 {
							fmt.Printf("\r- lookup %d user-agents (found %d) ", total, atomic.LoadInt32(&found))
						}
					}
				}
				close(queue)
				waiter.Wait()
				fmt.Printf("\r- lookup %d user-agents (found %d / %d unknown / %v)\n",
					total, atomic.LoadInt32(&found), total-atomic.LoadInt32(&found), time.Since(start))
			}
			time.Sleep(time.Second)
		}
		db.Load(os.Args[2])
		fmt.Printf("- reloaded database (version %s)\n", db.Version)
	}
}

func server() {
	db := uadb.New()
	if err := db.Load(os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "%v - aborting\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "- opened database %s (version %s)\n", os.Args[3], db.Version)

	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGHUP)
		for {
			<-signals
			if err := db.Load(os.Args[3]); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "- reloaded database %s (version %s)\n", os.Args[3], db.Version)
			}
		}
	}()

	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		lookup, code := make(map[string]string, 24), strings.ToLower(request.URL.Query().Get("code"))
		db.Lookup(request.Header.Get("User-Agent"), lookup, code == "1" || code == "true" || code == "on" || code == "yes")
		if request.Method == http.MethodHead {
			for key, value := range lookup {
				response.Header().Set("X-"+strings.ReplaceAll(key, "_", "-"), value)
			}
		} else {
			response.Header().Set("Content-Type", "application/json")
			data, _ := json.Marshal(lookup)
			response.Write(data)
		}
	})
	parts := strings.Split(os.Args[2], ",")
	server := &http.Server{Addr: strings.TrimLeft(parts[0], "*"), ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "- started server listening to %s\n", os.Args[2])
	if len(parts) > 1 {
		server.ListenAndServeTLS(parts[1], parts[2])
	} else {
		server.ListenAndServe()
	}
}

func usage(status int) {
	fmt.Fprintf(os.Stderr, "usage: uadb <action> [parameters...]\n\n"+
		"help                                  show this help screen\n"+
		"build  <database> <udger-database>    build database from UdgerV3 database\n"+
		"lookup <database> <user-agent>...     lookup user-agents in database\n"+
		"bench  <database> <user-agents-file>  user-agents lookup bench\n"+
		"server <bind address> <database>      spawn an HTTP(S) server for user-agents lookup\n")
	os.Exit(status)
}

func main() {
	if len(os.Args) < 2 {
		usage(1)
	}
	switch os.Args[1] {
	case "help":
		usage(0)
	case "build":
		if len(os.Args) < 4 {
			usage(1)
		}
		build()
	case "lookup":
		if len(os.Args) < 4 {
			usage(1)
		}
		lookup()
	case "bench":
		if len(os.Args) < 4 {
			usage(1)
		}
		bench()
	case "server":
		if len(os.Args) < 4 {
			usage(1)
		}
		server()
	default:
		usage(2)
	}
}
