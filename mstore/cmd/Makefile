mstore: mstore.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath mstore.go
	@-strip mstore 2>/dev/null || true

run: mstore
	@./mstore info _metrics sites/ping/ATL-SIN
	@#./mstore export _metrics sites/ping/ATL-SIN
	@#./mstore import _metrics sites/ping/ATL-SIN

clean:
	@rm -rf mstore _metrics
