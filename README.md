A collection of Go utility/support libraries.

- acl:
  IP CIDR-based access control (CIDR, CIDRConfig) and time-range ACL matching (Ranges, RangesConfig) with day-of-week and time-of-day support.

- auth:
  Authentication helpers: SHA-512 crypt (Crypt512, fully implements the SHA-crypt spec from akkadia.org), password file matching (Password, PasswordFile, PasswordConfig), JWT token encode/decode (TokenEncode, TokenDecode) supporting HS256, RS256, ES256, EdDSA.

- bslab:
  Byte-slice slab allocator / memory pool. Manages power-of-two sized byte slices (256B to 64MB) via buffered channels. Supports per-arena instances, tracing by caller/size, and statistics.

- chash:
  Consistent hashing ring using Murmur2. Supports weighted targets, serialization/deserialization to binary format, and randomized load balancing across top-N results.

- dynacert:
  Dynamic TLS certificate loader. Watches certificate files for modification (every 15 seconds), supports inline in-memory certs, SNI-based matching via regex, and produces a tls.Config with GetCertificate hook. Forces TLS 1.3 minimum.

- expect:
  SSH client automation library with text/JSON/XML output modes, NETCONF subsystem support (RFC 6241), idle timeout, host key auto-accept, XML/JSON parsing, and a Mapper for extracting structured data.

- file:
  Filesystem utility functions: Read (line-by-line with regex filter/capture), Write (create/append/truncate), Touch, Exists, IsRegular, IsDir, Link, Sum (SHA-256), Copy.

- fqdn:
  Resolves the local machine’s fully qualified domain name and primary IP address.

- jsonrpc:
  Full JSON-RPC 2.0 client and server: request building, response parsing, HTTP transport, batch requests, server-side routing with authorization filter, goroutine-per-call dispatch, panic recovery. Also provides extensive type coercion helpers (Boolean, String, Number, Slice, Map, StringSlice, etc.) and Flatten, Size, SizeBounds, Duration, DurationBounds.

- listener:
  TCP listener with SO_REUSEPORT support, HAProxy PROXY protocol v2 parsing (with CRC32c TLV verification), TLS ClientHello SNI hijacking, keepalive configuration, and per-connection attributes.

- mstore:
  Append-only columnar time-series metric store backed by memory-mapped files (one file per calendar month). Supports gauge, counter, increment, text, and binary column types. Aggregation: min, max, sum, average, first, last, histogram, percentile, raw. Text/binary columns use CRC32-keyed mapping tables.

- multiflag:
  flag.Value implementation for repeated key:value CLI flags.

- netlink:
  Linux netlink (RTNETLINK) interface management: enumerate interfaces/addresses, create/remove VLAN, veth pair, bridge, bond, set state/MTU/hwaddr/queue/namespace, add/remove IP addresses, routes enumeration, etc.

- prefixdb:
  Custom binary IP prefix lookup database format (PFDB). Stores a radix trie over IPv4/IPv6 prefixes with associated key-value pairs (strings, numbers, booleans). Supports clustered/shared dictionaries for compression. Falls back to capital city coordinates for country-code lookups with zero lat/lon.

- process:
  Process utilities: Self() (own executable path), Exec() (run command with timeout, optional stdin, environment, regex filtering), Task() (find processes by cmdline regex on Linux via /proc), Affinity() (set CPU affinity via SchedSetaffinity).

- rcache:
  Thread-safe compiled regular expression cache. LRU-like cap at 4096 entries. Returns a no-match sentinel for invalid or oversized expressions.

- rpack:
  Static resource packer: walks a directory tree, gzip-compresses each file, base64-encodes it, and writes a Go source file with an embedded map and HTTP handler. Also supports serving multiple resources concatenated (gzip stream combining via CRC combining).

- ubgp:
  Full BGP-4 speaker implementation (RFC 4271). Supports: multi-group/multi-speaker/peer architecture, BGP FSM (idle/active/connect/open-sent/open-confirm/established), OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH messages, extended messages, ASN4 (RFC 6793), multi-protocol (RFC 4760), add-path (RFC 7911), route-refresh, graceful restart, EOR, communities, passive (listening) and active modes, callbacks via Processor interface.

- uconfig:
  Flexible configuration file parser. Accepts files or inline strings. Supports a superset of JSON with comments (#, //, /* */), macros (<<~file>>, <<^file>>, etc.).

- uhash:
  Hash utilities: Rand(n) (crypto random int), Key(size) (URL-safe random key string up to 256 chars), CRC16 (Internet checksum over multiple byte buffers).

- uio:
  Hardware I/O: Linux serial port (full termios config, poll-based read/write, RTS/DTR control), GPIO (Linux GPIO character device v2 via ioctl, line info enumeration), I2C, SPI, PWM.

- ulog:
  Structured and unstructured logger. Targets: syslog (local or UDP remote), file (with strftime-style rotation patterns, auto-close of idle handles, purge by age/count, gzip compression of old files), console (color-coded output with ANSI escapes). Supports log levels, structured map[string]any payloads with JSON encoding, ordered fields, template substitutions, and external log callbacks.

- ustr:
  String utilities: Wrap (error wrapping), Bool/Int/Float/String (formatted padding/alignment), Truncate (UTF-8 aware), Hex/HexInt/IPv4/Pointer (encoding), Binary (hex decode), Range (integer range parser), Duration/Size/Bandwidth/Plural (human-readable formatting), Strftime (C-style time formatting), Transform/Options (trim/lower/upper/space/empty/first/json).

- uuid:
  RFC4122 UUID v4 generation using crypto/rand. Parse (Unmarshal), validate (Check), and stringify (String).

- uws:
  WebSocket (RFC 6455) client and server. Full frame parser with masking, fragmentation, ping/pong, close handshake, PROXY protocol support, TLS, HTTP proxy CONNECT tunneling, inactive timeout, and arena-backed receive buffer.
