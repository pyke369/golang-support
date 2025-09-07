package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uadb"
	"github.com/pyke369/golang-support/ustr"
)

func build() {
	rewriter, target := rcache.Get(`^/(.+)/([gims]*)$`), uadb.New()

	if source, err := sql.Open("sqlite3", os.Args[3]); err == nil {
		if row := source.QueryRow("select version from udger_db_info"); row != nil {
			if row.Scan(&target.Version) == nil && target.Version != "" {
				os.Stderr.WriteString("- opened source database " + os.Args[3] + " (version " + target.Version + ")\n")
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
				os.Stderr.WriteString("- loaded " + strconv.Itoa(len(target.Agents)) + " user-agent(s)\n")

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
				os.Stderr.WriteString("- loaded " + strconv.Itoa(len(target.Devices)) + " device(s)\n")

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
				os.Stderr.WriteString("- loaded " + strconv.Itoa(len(target.Systems)) + " operating system(s)\n")

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
				os.Stderr.WriteString("- loaded " + strconv.Itoa(len(target.Crawlers)) + " crawler(s)\n")

				if payload, err := json.Marshal(target); err == nil {
					if os.WriteFile(os.Args[2], payload, 0o644) == nil {
						os.Stderr.WriteString("- saved target database " + os.Args[2] + " (" + strconv.Itoa(len(payload)) + " bytes)\n")
					}
				}
			}
		}
	}
}

func lookup() {
	db := uadb.New()
	if err := db.Load(os.Args[2]); err != nil {
		os.Stdout.WriteString(err.Error() + " - exiting\n")
		return
	}
	os.Stdout.WriteString("- loaded database (version " + db.Version + ")\n")
	for _, agent := range os.Args[3:] {
		os.Stdout.WriteString("- " + agent + "\n")
		lookup, keys := make(map[string]string, 24), []string{}
		db.Lookup(agent, lookup, true)
		for key := range lookup {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			os.Stdout.WriteString("  " + ustr.String(key, -20) + "  " + lookup[key] + "\n")
		}
	}
}

func bench() {
	db, concurrency := uadb.New(), runtime.NumCPU()*2
	if err := db.Load(os.Args[2]); err != nil {
		os.Stdout.WriteString(err.Error() + " - exiting\n")
		return
	}
	os.Stdout.WriteString("- loaded database (version " + db.Version + ")\n")

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
							os.Stdout.WriteString("\r- lookup " + strconv.Itoa(int(total)) +
								" user-agents (found " + strconv.Itoa(int(atomic.LoadInt32(&found))) + ") ")
						}
					}
				}
				close(queue)
				waiter.Wait()
				os.Stdout.WriteString("\r- lookup " + strconv.Itoa(int(total)) + " user-agents (found " + strconv.Itoa(int(atomic.LoadInt32(&found))) +
					" / " + strconv.Itoa(int(total-atomic.LoadInt32(&found))) + " unknown / " + ustr.Duration(time.Since(start)) + ")\n")
			}
			time.Sleep(time.Second)
		}
		db.Load(os.Args[2])
		os.Stdout.WriteString("- reloaded database (version " + db.Version + ")\n")
	}
}

func server() {
	db := uadb.New()
	if err := db.Load(os.Args[3]); err != nil {
		os.Stderr.WriteString(err.Error() + " - aborting\n")
		return
	}
	os.Stderr.WriteString("- opened database " + os.Args[3] + " (version " + db.Version + ")\n")

	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGHUP)
		for {
			<-signals
			if err := db.Load(os.Args[3]); err != nil {
				os.Stderr.WriteString(err.Error() + "\n")

			} else {
				os.Stderr.WriteString("- reloaded database " + os.Args[3] + " (version " + db.Version + ")\n")
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
			response.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			response.Write(data)
		}
	})
	parts := strings.Split(os.Args[2], ",")
	server := &http.Server{Addr: strings.TrimLeft(parts[0], "*"), ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	os.Stderr.WriteString("- started server (listening to " + os.Args[2] + ")\n")
	if len(parts) > 1 {
		server.ListenAndServeTLS(parts[1], parts[2])

	} else {
		server.ListenAndServe()
	}
}

func usage(status int) {
	os.Stderr.WriteString(`usage: uadb <action> [parameters...]

help                                  show this help screen
build  <database> <udger-database>    build database from UdgerV3 database
lookup <database> <user-agent>...     lookup user-agents in database
bench  <database> <user-agents-file>  user-agents lookup bench
server <bind address> <database>      spawn an HTTP(S) server for user-agents lookup
`)
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
