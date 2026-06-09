//go:build go1.24

package uws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uhash"
	"github.com/pyke369/golang-support/ustr"
	"golang.org/x/net/http/httpproxy"
)

const (
	UUID              = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	VERSION           = "13"
	FIN               = 0x80
	MASK              = 0x80
	OPCODE_TEXT       = 1
	OPCODE_BLOB       = 2
	OPCODE_BINARY     = 2
	OPCODE_CLOSE      = 8
	OPCODE_PING       = 9
	OPCODE_PONG       = 10
	ERROR_NORMAL      = 1000
	ERROR_AWAY        = 1001
	ERROR_PROTOCOL    = 1002
	ERROR_UNSUPPORTED = 1003
	ERROR_ABNORMAL    = 1006
	ERROR_INVALID     = 1007
	ERROR_OVERSIZED   = 1009
)

type Config struct {
	Proxy           func(*url.URL) (*url.URL, error)
	TLSConfig       *tls.Config
	Headers         map[string]string
	Protocols       []string
	NeedProtocol    bool
	ReadSize        int
	FragmentSize    int
	MessageSize     int
	ConnectTimeout  time.Duration
	ProbeTimeout    time.Duration
	InactiveTimeout time.Duration
	WriteTimeout    time.Duration
	WriteBufferSize int
	ReadBufferSize  int
	OriginHandler   func(string) bool
	OpenHandler     func(*Socket)
	CloseHandler    func(*Socket, int)
	MessageHandler  func(*Socket, int, []byte) bool
	Context         any
	Arena           *bslab.Arena
}

type Socket struct {
	Path, Origin, Agent, Remote, Protocol string
	Context                               any
	config                                *Config
	conn                                  net.Conn
	connected, errored                    atomic.Bool
	client, closing                       bool
	wlock, slock, clock                   sync.Mutex
}

var (
	proxy func(*url.URL) (*url.URL, error)
	gnow  int64
)

func init() {
	proxy = httpproxy.FromEnvironment().ProxyFunc()
	atomic.StoreInt64(&gnow, time.Now().UnixNano())
	go func() {
		for {
			atomic.StoreInt64(&gnow, time.Now().UnixNano())
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func Dial(endpoint, origin string, config *Config) (ws *Socket, err error) {
	if config == nil {
		config = &Config{}
	}
	if config.Proxy == nil {
		config.Proxy = proxy
	}
	config.ReadSize = cval(config.ReadSize, 64<<10, 4<<10, 1<<20)
	config.FragmentSize = cval(config.FragmentSize, 64<<10, 4<<10, 1<<20)
	config.MessageSize = cval(config.MessageSize, 64<<10, 4<<10, 4<<20)
	config.ConnectTimeout = time.Duration(cval(int(config.ConnectTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
	config.ProbeTimeout = time.Duration(cval(int(config.ProbeTimeout), int(15*time.Second), int(1*time.Second), int(30*time.Second)))
	config.InactiveTimeout = time.Duration(cval(int(config.InactiveTimeout), int(3*config.ProbeTimeout), int(config.ProbeTimeout+time.Second), int(5*config.ProbeTimeout)))
	config.WriteTimeout = time.Duration(cval(int(config.WriteTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
	if config.ReadBufferSize != 0 {
		config.ReadBufferSize = cval(config.ReadBufferSize, 1<<20, 4<<10, 4<<20)
	}
	if config.WriteBufferSize != 0 {
		config.WriteBufferSize = cval(config.WriteBufferSize, 1<<20, 4<<10, 4<<20)
	}
	if config.Arena == nil {
		config.Arena = bslab.Default
	}
	endpoint = strings.Replace(strings.Replace(endpoint, "ws:", "http:", 1), "wss:", "https:", 1)
	if eurl, err := url.Parse(endpoint); err == nil {
		rproxy, _ := config.Proxy(eurl)
		if request, err := http.NewRequest("GET", endpoint, http.NoBody); err == nil {
			nonce := uhash.RandKey(16, "std")
			request.Header.Add("User-Agent", "uws")
			request.Header.Add("Connection", "Upgrade")
			request.Header.Add("Upgrade", "websocket")
			request.Header.Add("Sec-WebSocket-Version", VERSION)
			request.Header.Add("Sec-WebSocket-Key", nonce)
			if len(config.Protocols) > 0 {
				request.Header.Add("Sec-WebSocket-Protocol", strings.Join(config.Protocols, ", "))
			}
			if origin != "" {
				request.Header.Add("Origin", origin)
			}
			for name, value := range config.Headers {
				request.Header.Add(name, value)
			}

			start, scheme, address := time.Now(), eurl.Scheme, eurl.Host
			if rproxy != nil {
				scheme, address = rproxy.Scheme, rproxy.Host
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
			defer cancel()
			if conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address); err == nil {
				if tconn, ok := conn.(*net.TCPConn); ok {
					if config.ReadBufferSize != 0 {
						tconn.SetReadBuffer(config.ReadBufferSize)
					}
					if config.WriteBufferSize != 0 {
						tconn.SetWriteBuffer(config.WriteBufferSize)
					}
				}
				if scheme == "https" {
					if config.TLSConfig == nil {
						config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}

					} else {
						config.TLSConfig = config.TLSConfig.Clone()
					}
					config.TLSConfig.MinVersion = tls.VersionTLS13
					if config.TLSConfig.ServerName == "" {
						config.TLSConfig.ServerName = address
						if value, _, err := net.SplitHostPort(address); err == nil {
							config.TLSConfig.ServerName = value
						}
					}
					conn = tls.Client(conn, config.TLSConfig)
					if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
						conn.Close()
						return nil, ustr.Wrap(err, "uws")
					}
				}
				if rproxy != nil {
					host, port := eurl.Host, "0"
					if value1, value2, err := net.SplitHostPort(host); err == nil {
						host, port = value1, value2
					}
					if port == "0" {
						if eurl.Scheme == "https" {
							port = "443"

						} else {
							port = "80"
						}
					}

					request, err := http.NewRequest(http.MethodConnect, host+":"+port, http.NoBody)
					if err != nil {
						conn.Close()
						return nil, ustr.Wrap(err, "uws")
					}
					if user := rproxy.User; user != nil {
						password, _ := user.Password()
						request.SetBasicAuth(user.Username(), password)
					}

					conn.SetWriteDeadline(time.Now().Add(config.ConnectTimeout - time.Since(start)))
					if err := request.Write(conn); err != nil {
						conn.Close()
						return nil, ustr.Wrap(err, "uws")
					}
					conn.SetReadDeadline(time.Now().Add(config.ConnectTimeout))
					if response, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
						response.Body.Close()
						if response.StatusCode != 200 {
							conn.Close()
							return nil, errors.New("uws: invalid proxy connection http status")
						}

					} else {
						conn.Close()
						return nil, ustr.Wrap(err, "uws")
					}

					if eurl.Scheme == "https" {
						if config.TLSConfig == nil {
							config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}

						} else {
							config.TLSConfig = config.TLSConfig.Clone()
						}
						config.TLSConfig.MinVersion = tls.VersionTLS13
						config.TLSConfig.ServerName = host
						conn = tls.Client(conn, config.TLSConfig)
						if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
							conn.Close()
							return nil, ustr.Wrap(err, "uws")
						}
					}
				}

				conn.SetWriteDeadline(time.Now().Add(config.ConnectTimeout - time.Since(start)))
				if err := request.Write(conn); err != nil {
					conn.Close()
					return nil, ustr.Wrap(err, "uws")
				}
				conn.SetReadDeadline(time.Now().Add(config.ConnectTimeout))
				if response, err := http.ReadResponse(bufio.NewReader(conn), request); err == nil {
					skey, _ := base64.StdEncoding.DecodeString(response.Header.Get("Sec-WebSocket-Accept"))
					ckey, path := sha1.Sum([]byte(nonce+UUID)), eurl.Path
					if path == "" {
						path = "/"
					}
					if response.StatusCode != http.StatusSwitchingProtocols || strings.ToLower(response.Header.Get("Connection")) != "upgrade" ||
						strings.ToLower(response.Header.Get("Upgrade")) != "websocket" || !bytes.Equal(ckey[:], skey) {
						response.Body.Close()
						conn.Close()
						return nil, errors.New("uws: protocol upgrade http status " + strconv.Itoa(response.StatusCode))
					}
					protocol := response.Header.Get("Sec-WebSocket-Protocol")
					if len(config.Protocols) > 0 && protocol == "" && config.NeedProtocol {
						response.Body.Close()
						conn.Close()
						return nil, errors.New(`uws: could not negotiate sub-protocol with server`)
					}
					ws = &Socket{
						Path:     path,
						Origin:   origin,
						Remote:   conn.RemoteAddr().String(),
						Protocol: protocol,
						Context:  config.Context,
						config:   config,
						conn:     conn,
						client:   true,
					}
					ws.connected.Store(true)
					if config.OpenHandler != nil {
						config.OpenHandler(ws)
					}
					go ws.receive(nil)

				} else {
					conn.Close()
					return nil, ustr.Wrap(err, "uws")
				}

			} else {
				return nil, ustr.Wrap(err, "uws")
			}

		} else {
			return nil, ustr.Wrap(err, "uws")
		}

	} else {
		return nil, ustr.Wrap(err, "uws")
	}

	return
}

func Handle(rw http.ResponseWriter, r *http.Request, config *Config) (handled bool, ws *Socket) {
	if config == nil {
		config = &Config{}
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") && strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		handled = true
		if r.Method != http.MethodGet {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ckey := r.Header.Get("Sec-WebSocket-Key")
		if r.Header.Get("Sec-WebSocket-Version") != VERSION || ckey == "" {
			rw.Header().Set("Sec-WebSocket-Version", VERSION)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := rw.(http.Hijacker); !ok {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		cprotocols, sprotocols, protocol := []string{}, map[string]bool{}, ""
		if len(config.Protocols) > 0 {
			if splitter := rcache.Get("[, ]+"); splitter != nil {
				cprotocols = splitter.Split(r.Header.Get("Sec-WebSocket-Protocol"), 10)
			}
			if len(cprotocols) > 0 {
				for _, value := range config.Protocols {
					sprotocols[value] = true
				}
				for _, value := range cprotocols {
					if sprotocols[value] {
						protocol = value
					}
				}
			}
			if protocol != "" {
				rw.Header().Set("Sec-WebSocket-Protocol", protocol)

			} else if config.NeedProtocol {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		origin := r.Header.Get("Origin")
		if strings.EqualFold(origin, "null") {
			origin = ""
		}
		if config.OriginHandler == nil {
			host := r.Host
			if host == "" {
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			if value, _, err := net.SplitHostPort(host); err == nil {
				host = value
			}
			value, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(value.Hostname(), host) {
				rw.WriteHeader(http.StatusForbidden)
				return
			}

		} else if !config.OriginHandler(origin) {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		skey := sha1.Sum([]byte(ckey + UUID))
		rw.Header().Set("Connection", "Upgrade")
		rw.Header().Set("Upgrade", "websocket")
		rw.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(skey[:]))
		rw.WriteHeader(http.StatusSwitchingProtocols)
		if conn, reader, err := rw.(http.Hijacker).Hijack(); err == nil {
			conn.SetDeadline(time.Time{})
			if config == nil {
				config = &Config{}
			}
			config.ReadSize = cval(config.ReadSize, 64<<10, 4<<10, 1<<20)
			config.FragmentSize = cval(config.FragmentSize, 64<<10, 4<<10, 1<<20)
			config.MessageSize = cval(config.MessageSize, 64<<10, 4<<10, 4<<20)
			config.ProbeTimeout = time.Duration(cval(int(config.ProbeTimeout), int(15*time.Second), int(1*time.Second), int(30*time.Second)))
			config.InactiveTimeout = time.Duration(cval(int(config.InactiveTimeout), int(3*config.ProbeTimeout), int(config.ProbeTimeout+time.Second), int(5*config.ProbeTimeout)))
			config.WriteTimeout = time.Duration(cval(int(config.WriteTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
			if config.ReadBufferSize != 0 {
				config.ReadBufferSize = cval(config.ReadBufferSize, 1<<20, 4<<10, 4<<20)
			}
			if config.WriteBufferSize != 0 {
				config.WriteBufferSize = cval(config.WriteBufferSize, 1<<20, 4<<10, 4<<20)
			}
			if config.Arena == nil {
				config.Arena = bslab.Default
			}
			if tconn, ok := conn.(*net.TCPConn); ok {
				if config.ReadBufferSize != 0 {
					tconn.SetReadBuffer(config.ReadBufferSize)
				}
				if config.WriteBufferSize != 0 {
					tconn.SetWriteBuffer(config.WriteBufferSize)
				}
			}
			ws = &Socket{
				Path:     r.URL.Path,
				Origin:   origin,
				Agent:    r.Header.Get("User-Agent"),
				Remote:   conn.RemoteAddr().String(),
				Protocol: protocol,
				Context:  config.Context,
				config:   config,
				conn:     conn,
			}
			ws.connected.Store(true)
			if config.OpenHandler != nil {
				config.OpenHandler(ws)
			}
			go ws.receive(reader)
		}
		return
	}
	return
}

func (s *Socket) Write(mode byte, data []byte) (err error) {
	var mask []byte

	length := len(data)
	if (mode == OPCODE_TEXT || mode == OPCODE_BLOB) && length > 0 {
		s.wlock.Lock()
		defer s.wlock.Unlock()
		frames := length / s.config.FragmentSize
		if length%s.config.FragmentSize != 0 {
			frames++
		}
		for frame := 1; frame <= frames; frame++ {
			fin, offset, size := byte(0), (frame-1)*s.config.FragmentSize, s.config.FragmentSize
			if frame == frames {
				fin, size = FIN, length-offset
			}
			if frame > 1 {
				mode = 0
			}
			payload := net.Buffers{[]byte{fin | mode, 0}}
			switch {
			case size < 126:
				payload[0][1] |= byte(size)

			case size < 65536:
				payload[0][1] |= 126
				payload = append(payload, []byte{0, 0})
				binary.BigEndian.PutUint16(payload[1], uint16(size))

			default:
				payload[0][1] |= 127
				payload = append(payload, []byte{0, 0, 0, 0, 0, 0, 0, 0})
				binary.BigEndian.PutUint64(payload[1], uint64(size))
			}
			if s.client {
				payload[0][1] |= MASK
				mask = rmask()
				payload = append(payload, mask)
				xor(mask, data[offset:offset+size])
			}
			payload = append(payload, data[offset:offset+size])
			err = s.send(payload)
			if s.client {
				xor(mask, data[offset:offset+size])
			}
			if err != nil {
				return
			}
		}
	}
	return
}

func (s *Socket) Close(code int) {
	s.clock.Lock()
	if !s.closing {
		s.closing = true
		s.clock.Unlock()
		if s.config != nil && s.config.CloseHandler != nil {
			s.config.CloseHandler(s, code)
		}
		if !s.errored.Load() {
			payload := net.Buffers{[]byte{FIN | OPCODE_CLOSE, 0}}
			if s.client {
				payload[0][1] |= MASK
				payload = append(payload, rmask())
			}
			if code != 0 {
				payload[0][1] |= 2
				payload = append(payload, []byte{0, 0})
				binary.BigEndian.PutUint16(payload[len(payload)-1], uint16(code))
				if s.client {
					xor(payload[1], payload[2])
				}
			}
			s.send(payload)
		}
		s.connected.Store(false)
		s.conn.Close()
		return
	}
	s.clock.Unlock()
}

func (s *Socket) send(payload net.Buffers) (err error) {
	s.slock.Lock()
	defer s.slock.Unlock()
	if !s.connected.Load() || s.errored.Load() {
		return errors.New(`uws: not connected`)
	}
	s.conn.SetWriteDeadline(time.UnixMicro(atomic.LoadInt64(&gnow) / int64(time.Microsecond)).Add(time.Duration(s.config.WriteTimeout)))
	if _, err = payload.WriteTo(s.conn); err != nil {
		s.errored.Store(true)
		s.Close(ERROR_ABNORMAL)
	}
	return
}

func (s *Socket) receive(buffered io.Reader) {
	var (
		data, control, buffer []byte
		err                   error
	)

	fin, opcode, size, mask, smask := byte(0), byte(0), -1, make([]byte, 4), 0
	seen, code, dmode, dsize, doffset, dlast := atomic.LoadInt64(&gnow), 0, byte(0), 0, 0, false
	roffset, woffset, read, buffer := 0, 0, 0, bslab.Get(s.config.ReadSize)
	buffer = buffer[:cap(buffer)]
	if !s.client {
		smask += 4
	}
close:
	for {
		if cap(buffer)-roffset < 14 {
			copy(buffer[0:], buffer[roffset:woffset])
			woffset -= roffset
			roffset = 0
		}

		s.conn.SetReadDeadline(time.UnixMicro(atomic.LoadInt64(&gnow) / int64(time.Microsecond)).Add(time.Duration(s.config.ProbeTimeout)))
		if buffered != nil {
			read, err = buffered.Read(buffer[woffset:])
			buffered = nil

		} else {
			read, err = s.conn.Read(buffer[woffset:])
		}

		if read > 0 {
			seen = atomic.LoadInt64(&gnow)
			woffset += read
		readmore:
			for {
				if size < 0 {
					if woffset-roffset < 2 {
						break
					}

					fin, opcode, size = buffer[roffset]>>7, buffer[roffset]&0x0f, int(buffer[roffset+1]&0x7f)
					if (s.client && (buffer[roffset+1]&MASK) != 0) || (!s.client && (buffer[roffset+1]&MASK) == 0) ||
						(fin == 0 && opcode >= OPCODE_CLOSE && opcode <= OPCODE_PONG) ||
						(opcode != 0 && opcode != OPCODE_TEXT && opcode != OPCODE_BLOB && (opcode < OPCODE_CLOSE || opcode > OPCODE_PONG)) ||
						((opcode == OPCODE_PING || opcode == OPCODE_PONG) && size > 125) {
						code = ERROR_PROTOCOL
						break close
					}
					if !s.client && woffset-roffset < 2+smask {
						size = -1
						break
					}
					if opcode == OPCODE_TEXT || opcode == OPCODE_BLOB {
						dmode = opcode
					}
					if dmode != 0 && fin == 1 {
						dlast = true
					}

					switch {
					case size == 126:
						if woffset-roffset < 4+smask {
							size = -1
							break readmore
						}
						size = int(binary.BigEndian.Uint16(buffer[roffset+2:]))
						if !s.client {
							copy(mask, buffer[roffset+4:])
						}
						roffset += 4 + smask

					case size == 127:
						if woffset-roffset < 10+smask {
							size = -1
							break readmore
						}
						rsize := binary.BigEndian.Uint64(buffer[roffset+2:])
						if rsize > uint64(s.config.MessageSize) || rsize > uint64(math.MaxInt) {
							code = ERROR_OVERSIZED
							break close
						}
						size = int(rsize)
						if !s.client {
							copy(mask, buffer[roffset+10:])
						}
						roffset += 10 + smask

					default:
						if !s.client {
							copy(mask, buffer[roffset+2:])
						}
						roffset += 2 + smask
					}
					if (opcode <= OPCODE_BLOB && size == 0) || (opcode > OPCODE_BLOB && size > 125) || (fin == 1 && size > s.config.MessageSize) {
						code = ERROR_OVERSIZED
						break close
					}
					if dmode != 0 {
						dsize += size
					}
				}

				if size >= 0 {
					if dmode != 0 {
						if data == nil {
							data = s.config.Arena.Get(dsize)
						}
						highest := min(woffset-roffset, size)
						if len(data)+highest > s.config.MessageSize {
							code = ERROR_OVERSIZED
							break close
						}
						data = append(data, buffer[roffset:roffset+highest]...)
						size -= highest
						roffset += highest
						if size <= 0 && len(data) >= dsize {
							if !s.client {
								xor(mask, data[doffset:dsize])
							}
							doffset = dsize
							if dlast {
								if dmode == OPCODE_TEXT && !utf8.Valid(data) {
									code = ERROR_INVALID
									break close
								}
								keep := false
								if s.config.MessageHandler != nil {
									keep = s.config.MessageHandler(s, int(dmode), data)
								}
								if !keep {
									s.config.Arena.Put(data)
								}
								dmode, dsize, doffset, dlast, data = 0, 0, 0, false, nil
							}
							size = -1
						}

					} else {
						if control == nil {
							control = bslab.Get(132)
						}
						highest := min(woffset-roffset, size)
						control = append(control, buffer[roffset:roffset+highest]...)
						size -= highest
						roffset += highest
						if size <= 0 {
							if !s.client {
								xor(mask, control)
							}
							switch opcode {
							case OPCODE_CLOSE:
								if len(control) >= 2 {
									code = int(binary.BigEndian.Uint16(control))
								}
								break close

							case OPCODE_PING:
								payload := net.Buffers{[]byte{FIN | OPCODE_PONG, byte(len(control))}}
								if s.client {
									payload[0][1] |= MASK
									payload = append(payload, rmask())
									xor(payload[1], control)
								}
								if len(control) > 0 {
									payload = append(payload, control)
								}
								if err := s.send(payload); err != nil {
									break close
								}
							}
							bslab.Put(control)
							size, control = -1, nil
						}
					}
				}

				if roffset >= woffset {
					roffset, woffset = 0, 0
					break
				}
			}
		}

		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				payload := net.Buffers{[]byte{FIN | OPCODE_PING, 0}}
				if s.client {
					payload[0][1] |= MASK
					payload = append(payload, rmask())
				}
				if err := s.send(payload); err != nil {
					break close
				}

			} else {
				code = ERROR_ABNORMAL
				break close
			}

		} else if read == 0 {
			code = ERROR_ABNORMAL
			break close
		}

		if atomic.LoadInt64(&gnow)-seen >= int64(s.config.InactiveTimeout) {
			code = ERROR_PROTOCOL
			break close
		}
	}
	bslab.Put(buffer)
	if control != nil {
		bslab.Put(control)
	}
	if data != nil {
		s.config.Arena.Put(data)
	}
	s.Close(code)
}

func rmask() []byte {
	value := []byte{0, 0, 0, 0}
	rand.Read(value)

	return value
}

func cval(value, fallback, lowest, highest int) int {
	if value == 0 {
		value = fallback
	}

	return min(max(value, lowest), highest)
}

func xor(mask, data []byte) {
	if len(mask) == 0 || len(data) == 0 {
		return
	}

	smask := bytes.Repeat(mask, max(len(mask), min(4<<10, len(data)))/len(mask))
	for index := 0; index < len(data); index += len(smask) {
		subtle.XORBytes(data[index:], data[index:], smask)
	}
}
