package uws

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uuid"
)

const (
	WEBSOCKET_UUID            = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	WEBSOCKET_VERSION         = "13"
	WEBSOCKET_FIN             = 0x80
	WEBSOCKET_MASK            = 0x80
	WEBSOCKET_OPCODE_TEXT     = 1
	WEBSOCKET_OPCODE_BLOB     = 2
	WEBSOCKET_OPCODE_CLOSE    = 8
	WEBSOCKET_OPCODE_PING     = 9
	WEBSOCKET_OPCODE_PONG     = 10
	WEBSOCKET_ERROR_PROTOCOL  = 1002
	WEBSOCKET_ERROR_INVALID   = 1007
	WEBSOCKET_ERROR_OVERSIZED = 1009
)

type Config struct {
	Protocols       []string
	NeedProtocol    bool
	ReadSize        int
	FragmentSize    int
	MessageSize     int
	ConnectTimeout  time.Duration
	ProbeTimeout    time.Duration
	InactiveTimeout time.Duration
	WriteTimeout    time.Duration
	OpenHandler     func(*Socket)
	MessageHandler  func(*Socket, int, []byte)
	CloseHandler    func(*Socket, int)
}

type Socket struct {
	Path, Origin, Agent, Remote, Protocol string
	config                                *Config
	conn                                  net.Conn
	connected, client                     bool
	wlock, dlock, clock                   sync.Mutex
}

func Dial(endpoint, origin string, config *Config) (ws *Socket, err error) {
	endpoint = strings.Replace(endpoint, "wss:", "https:", 1)
	endpoint = strings.Replace(endpoint, "ws:", "http:", 1)
	if config == nil {
		config = &Config{}
	}
	config.ReadSize = cval(config.ReadSize, 4<<10, 4<<10, 256<<10)
	config.FragmentSize = cval(config.FragmentSize, 16<<10, 4<<10, 256<<10)
	config.MessageSize = cval(config.MessageSize, 4<<20, 4<<10, 64<<20)
	config.ConnectTimeout = time.Duration(cval(int(config.ProbeTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
	config.ProbeTimeout = time.Duration(cval(int(config.ProbeTimeout), int(15*time.Second), int(1*time.Second), int(30*time.Second)))
	config.InactiveTimeout = time.Duration(cval(int(config.InactiveTimeout), int(3*config.ProbeTimeout), int(config.ProbeTimeout+time.Second), int(5*config.ProbeTimeout)))
	config.WriteTimeout = time.Duration(cval(int(config.WriteTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
	if request, err := http.NewRequest("GET", endpoint, nil); err == nil {
		var sconn net.Conn

		nonce := base64.StdEncoding.EncodeToString(uuid.BUUID())
		request.Header.Add("User-Agent", "uws")
		request.Header.Add("Connection", "Upgrade")
		request.Header.Add("Upgrade", "websocket")
		request.Header.Add("Sec-WebSocket-Version", WEBSOCKET_VERSION)
		request.Header.Add("Sec-WebSocket-Key", nonce)
		if len(config.Protocols) > 0 {
			request.Header.Add("Sec-WebSocket-Protocol", strings.Join(config.Protocols, ", "))
		}
		if origin != "" {
			request.Header.Add("Origin", origin)
		}
		client := &http.Client{Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				dialer := &net.Dialer{Timeout: 10 * time.Second}
				if conn, err = dialer.Dial(network, addr); err == nil {
					sconn = conn
				}
				return
			},
		}}
		if response, err := client.Do(request); err == nil {
			ckey, path := sha1.Sum([]byte(nonce+WEBSOCKET_UUID)), ""
			skey, _ := base64.StdEncoding.DecodeString(response.Header.Get("Sec-WebSocket-Accept"))
			if response.StatusCode != http.StatusSwitchingProtocols || strings.ToLower(response.Header.Get("Connection")) != "upgrade" ||
				strings.ToLower(response.Header.Get("Upgrade")) != "websocket" || !bytes.Equal(ckey[:], skey) || sconn == nil {
				response.Body.Close()
				return nil, errors.New("websocket: invalid protocol upgrade")
			}
			protocol := response.Header.Get("Sec-WebSocket-Protocol")
			if len(config.Protocols) > 0 && protocol == "" && config.NeedProtocol {
				response.Body.Close()
				return nil, errors.New("websocket: could not negotiate sub-protocol with server")
			}
			if parts, err := url.Parse(endpoint); err == nil {
				path = parts.Path
			}
			if path == "" {
				path = "/"
			}
			ws = &Socket{Path: path, Remote: sconn.RemoteAddr().String(), Origin: origin, Protocol: protocol,
				config: config, client: true, conn: sconn, connected: true}
			go ws.receive(response.Body)
			if config.OpenHandler != nil {
				config.OpenHandler(ws)
			}
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
	return
}

func Handle(response http.ResponseWriter, request *http.Request, config *Config) (handled bool, ws *Socket) {
	if strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") && strings.ToLower(request.Header.Get("Upgrade")) == "websocket" {
		handled = true
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ckey := request.Header.Get("Sec-WebSocket-Key")
		if request.Header.Get("Sec-WebSocket-Version") != WEBSOCKET_VERSION || ckey == "" {
			response.Header().Set("Sec-WebSocket-Version", WEBSOCKET_VERSION)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := response.(http.Hijacker); !ok {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		cprotocols, sprotocols, protocol := []string{}, map[string]bool{}, ""
		if len(config.Protocols) > 0 {
			if splitter := rcache.Get("[, ]+"); splitter != nil {
				cprotocols = splitter.Split(request.Header.Get("Sec-WebSocket-Protocol"), 10)
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
				response.Header().Set("Sec-WebSocket-Protocol", protocol)
			} else if config.NeedProtocol {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		skey := sha1.Sum([]byte(ckey + WEBSOCKET_UUID))
		response.Header().Set("Connection", "Upgrade")
		response.Header().Set("Upgrade", "websocket")
		response.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(skey[:]))
		response.WriteHeader(http.StatusSwitchingProtocols)
		if conn, reader, err := response.(http.Hijacker).Hijack(); err == nil {
			conn.SetDeadline(time.Time{})
			if config == nil {
				config = &Config{}
			}
			config.ReadSize = cval(config.ReadSize, 4<<10, 4<<10, 256<<10)
			config.FragmentSize = cval(config.FragmentSize, 16<<10, 4<<10, 256<<10)
			config.MessageSize = cval(config.MessageSize, 4<<20, 4<<10, 64<<20)
			config.ProbeTimeout = time.Duration(cval(int(config.ProbeTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
			config.InactiveTimeout = time.Duration(cval(int(config.InactiveTimeout), int(3*config.ProbeTimeout), int(config.ProbeTimeout+time.Second), int(5*config.ProbeTimeout)))
			config.WriteTimeout = time.Duration(cval(int(config.WriteTimeout), int(10*time.Second), int(1*time.Second), int(30*time.Second)))
			origin := request.Header.Get("Origin")
			if strings.ToLower(origin) == "null" {
				origin = ""
			}
			ws = &Socket{Path: request.URL.Path, Origin: origin, Agent: request.Header.Get("User-Agent"),
				Remote: conn.RemoteAddr().String(), Protocol: protocol, config: config, conn: conn, connected: true}
			go ws.receive(reader)
			if config.OpenHandler != nil {
				config.OpenHandler(ws)
			}
		}
		return
	}
	return
}

func (this *Socket) IsClient() bool {
	return this.client
}

func (this *Socket) IsConnected() bool {
	return this.connected
}

func (this *Socket) Write(mode byte, data []byte) (err error) {
	length := len(data)
	if (mode == WEBSOCKET_OPCODE_TEXT || mode == WEBSOCKET_OPCODE_BLOB) && length > 0 {
		this.dlock.Lock()
		defer this.dlock.Unlock()
		frames := length / this.config.FragmentSize
		if length%this.config.FragmentSize != 0 {
			frames++
		}
		for frame := 1; frame <= frames; frame++ {
			fin, offset, size := byte(0), (frame-1)*this.config.FragmentSize, this.config.FragmentSize
			if frame == frames {
				fin, size = WEBSOCKET_FIN, length-offset
			}
			if frame > 1 {
				mode = 0
			}
			payload := net.Buffers{[]byte{fin | mode, 0}}
			if size < 126 {
				payload[0][1] |= byte(size)
			} else if size < 65536 {
				payload[0][1] |= 126
				payload = append(payload, []byte{0, 0})
				binary.BigEndian.PutUint16(payload[1], uint16(size))
			} else {
				payload[0][1] |= 127
				payload = append(payload, []byte{0, 0, 0, 0, 0, 0, 0, 0})
				binary.BigEndian.PutUint64(payload[1], uint64(size))
			}
			if this.client {
				payload[0][1] |= WEBSOCKET_MASK
				payload = append(payload, rmask())
				xor(payload[len(payload)-1], data[offset:offset+size])
			}
			payload = append(payload, data[offset:offset+size])
			err = this.send(payload)
			if this.client {
				xor(payload[len(payload)-2], data[offset:offset+size])
			}
			if err != nil {
				return
			}
		}
	}
	return
}

func (this *Socket) Close(code int) {
	this.clock.Lock()
	if this.connected {
		if this.config != nil && this.config.CloseHandler != nil {
			this.config.CloseHandler(this, code)
		}
		payload := net.Buffers{[]byte{WEBSOCKET_FIN | WEBSOCKET_OPCODE_CLOSE, 0}}
		if this.client {
			payload[0][1] |= WEBSOCKET_MASK
			payload = append(payload, rmask())
		}
		if code != 0 {
			payload[0][1] |= 2
			payload = append(payload, []byte{0, 0})
			binary.BigEndian.PutUint16(payload[len(payload)-1], uint16(code))
			if this.client {
				xor(payload[1], payload[2])
			}
		}
		this.send(payload)
		this.connected = false
		this.conn.Close()
	}
	this.clock.Unlock()
}

func (this *Socket) send(payload net.Buffers) (err error) {
	if !this.connected {
		return errors.New("websocket: not connected")
	}
	this.wlock.Lock()
	this.conn.SetWriteDeadline(time.Now().Add(this.config.WriteTimeout))
	if _, err = payload.WriteTo(this.conn); err != nil {
		this.Close(0)
	}
	this.wlock.Unlock()
	return
}

func (this *Socket) receive(buffered io.Reader) {
	var data, control []byte
	var err error

	fin, opcode, size, mask, smask := byte(0), byte(0), -1, make([]byte, 4), 0
	seen, code, dmode, dsize, doffset, dlast := time.Now(), 0, byte(0), 0, 0, false
	buffer, roffset, woffset, read := bslab.Get(this.config.ReadSize, nil), 0, 0, 0
	buffer = buffer[:cap(buffer)]
	if !this.client {
		smask += 4
	}
close:
	for {
		if cap(buffer)-roffset < 14 {
			copy(buffer[0:], buffer[roffset:woffset])
			woffset -= roffset
			roffset = 0
		}

		this.conn.SetReadDeadline(time.Now().Add(this.config.ProbeTimeout))
		if buffered != nil {
			read, err = buffered.Read(buffer[woffset:])
			buffered = nil
		} else {
			read, err = this.conn.Read(buffer[woffset:])
		}

		if read > 0 {
			seen = time.Now()
			woffset += read
			for {
				if size < 0 {
					if woffset-roffset >= 2 {
						fin, opcode, size = buffer[roffset]>>7, buffer[roffset]&0x0f, int(buffer[roffset+1]&0x7f)
						if (this.client && (buffer[roffset+1]&WEBSOCKET_MASK) != 0) || (!this.client && (buffer[roffset+1]&WEBSOCKET_MASK) == 0) ||
							(fin == 0 && opcode >= WEBSOCKET_OPCODE_CLOSE && opcode <= WEBSOCKET_OPCODE_PONG) ||
							(opcode != 0 && opcode != WEBSOCKET_OPCODE_TEXT && opcode != WEBSOCKET_OPCODE_BLOB && (opcode < WEBSOCKET_OPCODE_CLOSE || opcode > WEBSOCKET_OPCODE_PONG)) {
							code = WEBSOCKET_ERROR_PROTOCOL
							break close
						}
						if !this.client && woffset-roffset < 2+smask {
							size = -1
							break
						}
						if opcode == WEBSOCKET_OPCODE_TEXT || opcode == WEBSOCKET_OPCODE_BLOB {
							dmode = opcode
						}
						if dmode != 0 && fin == 1 {
							dlast = true
						}
						if size == 126 {
							if woffset-roffset < 4+smask {
								size = -1
								break
							}
							size = int(binary.BigEndian.Uint16(buffer[roffset+2:]))
							if !this.client {
								copy(mask, buffer[roffset+4:])
							}
							roffset += 4 + smask
						} else if size == 127 {
							if woffset-roffset < 10+smask {
								size = -1
								break
							}
							size = int(binary.BigEndian.Uint64(buffer[roffset+2:]))
							if !this.client {
								copy(mask, buffer[roffset+10:])
							}
							roffset += 10 + smask
						} else {
							if !this.client {
								copy(mask, buffer[roffset+2:])
							}
							roffset += 2 + smask
						}
						if (opcode <= WEBSOCKET_OPCODE_BLOB && size == 0) || (opcode > WEBSOCKET_OPCODE_BLOB && size > 125) || (fin == 1 && size > this.config.MessageSize) {
							code = WEBSOCKET_ERROR_OVERSIZED
							break close
						}
						if dmode != 0 {
							dsize += size
						}
					} else {
						break
					}
				}

				if size >= 0 {
					if dmode != 0 {
						if data == nil {
							data = bslab.Get(dsize, nil)
						}
						max := int(math.Min(float64(woffset-roffset), float64(size)))
						if len(data)+max > this.config.MessageSize {
							code = WEBSOCKET_ERROR_OVERSIZED
							break close
						}
						data = append(data, buffer[roffset:roffset+max]...)
						size -= max
						roffset += max
						if size <= 0 && len(data) >= dsize {
							if !this.client {
								xor(mask, data[doffset:dsize])
							}
							doffset = dsize
							if dlast {
								if dmode == WEBSOCKET_OPCODE_TEXT && !utf8.Valid(data) {
									code = WEBSOCKET_ERROR_INVALID
									break close
								}
								if this.config.MessageHandler != nil {
									this.config.MessageHandler(this, int(dmode), data)
								}
								bslab.Put(data)
								dmode, dsize, doffset, dlast, data = 0, 0, 0, false, nil
							}
							size = -1
						}
					} else {
						if control == nil {
							control = bslab.Get(132, nil)
						}
						max := int(math.Min(float64(woffset-roffset), float64(size)))
						control = append(control, buffer[roffset:roffset+max]...)
						size -= max
						roffset += max
						if size <= 0 {
							if !this.client {
								xor(mask, control)
							}
							switch opcode {
							case WEBSOCKET_OPCODE_CLOSE:
								if len(control) >= 2 {
									code = int(binary.BigEndian.Uint16(control))
								}
								break close
							case WEBSOCKET_OPCODE_PING:
								payload := net.Buffers{[]byte{WEBSOCKET_FIN | WEBSOCKET_OPCODE_PONG, byte(len(control))}}
								if this.client {
									payload[0][1] |= WEBSOCKET_MASK
									payload = append(payload, rmask())
									xor(payload[1], control)
								}
								payload = append(payload, control)
								if err := this.send(payload); err != nil {
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
				payload := net.Buffers{[]byte{WEBSOCKET_FIN | WEBSOCKET_OPCODE_PING, 0}}
				if this.client {
					payload[0][1] |= WEBSOCKET_MASK
					payload = append(payload, rmask())
				}
				if err := this.send(payload); err != nil {
					break close
				}
			} else {
				break close
			}
		} else if read == 0 {
			break close
		}

		if time.Now().Sub(seen) >= this.config.InactiveTimeout {
			break close
		}
	}
	bslab.Put(buffer)
	bslab.Put(control)
	bslab.Put(data)
	this.Close(code)
}

func rmask() []byte {
	value := []byte{0, 0, 0, 0}
	rand.Read(value)
	return value
}

func cval(value, fallback, min, max int) int {
	if value == 0 {
		value = fallback
	}
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}

const xorsize = int(unsafe.Sizeof(uintptr(0)))

func xor(mask []byte, data []byte) {
	offset, length := 0, len(data)
	if length >= xorsize {
		var value [xorsize]byte

		for index := range value {
			value[index] = mask[index%4]
		}
		xorer := *(*uintptr)(unsafe.Pointer(&value))
		offset = (length / xorsize) * xorsize
		for index := 0; index < offset; index += xorsize {
			*(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&data[0])) + uintptr(index))) ^= xorer
		}
	}
	for index := offset; index < length; index++ {
		data[index] ^= mask[(index-offset)%4]
	}
}
