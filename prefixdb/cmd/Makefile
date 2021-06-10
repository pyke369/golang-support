prefixdb: prefixdb.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath prefixdb.go
	@-strip prefixdb 2>/dev/null || true

run: prefixdb
	@#./prefixdb city city.pfdb@'MMCITY 20190402' GeoIP2-City-Locations-en.csv GeoIP2-City-Blocks-IPv4.csv GeoIP2-City-Blocks-IPv6.csv
	@#./prefixdb asn asn.pfdb@'MMASN 20190402' GeoLite2-ASN-Blocks-IPv4.csv GeoLite2-ASN-Blocks-IPv6.csv
	@./prefixdb lookup city.pfdb asn.pfdb 78.193.67.63 188.65.124.26
	@#./prefixdb server *:8000 city.pfdb asn.pfdb

clean:
	@rm -f prefixdb *.pfdb
