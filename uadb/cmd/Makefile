uadb: uadb.go
	@env GOPATH=/tmp/go go build -trimpath uadb.go
	@-strip uadb 2>/dev/null || true

run: uadb
	@#./uadb build agents.uadb udgerdb_v3.dat
	@#./uadb lookup agents.uadb 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
	@#./uadb bench agents.uadb agents.txt
	@#./uadb server *:8000 agents.uadb

clean:
	@rm -f uadb
