package expect

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"

	"golang.org/x/crypto/ssh"
)

const (
	sshMaxConnections = 5
	sshIdleTimeout    = 120 * time.Second
	sshConnectTimeout = 10 * time.Second
	sshExecTimeout    = 30 * time.Second
)

type SSHCredentials struct {
	Username string
	Password string
	Key      string
}

type SSHOptions struct {
	Mode      string
	SubSystem string
	Marker    string
	Filter    string
}

type sshConnection struct {
	mu      sync.Mutex
	active  bool
	running bool
	last    time.Time
	client  *ssh.Client
	session *ssh.Session
	input   io.WriteCloser
	output  io.Reader
	result  chan []string
}

type sshTransport struct {
	remote  string
	idle    time.Duration
	config  *ssh.ClientConfig
	options *SSHOptions
	sync.Mutex
	connections []*sshConnection
}

var (
	sshTransports = map[string]*sshTransport{}
	sshLock       sync.Mutex
)

func init() {
	go func() {
		for range time.Tick(5 * time.Second) {
			sshLock.Lock()
			for _, transport := range sshTransports {
				transport.Lock()
				for _, conn := range transport.connections {
					if conn != nil && !conn.last.IsZero() {
						if time.Since(conn.last) >= transport.idle {
							conn.Reset()
						}
					}
				}
				transport.Unlock()
			}
			sshLock.Unlock()
		}
	}()
}

func (c *sshConnection) Reset() {
	c.mu.Lock()
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
	if c.result != nil {
		close(c.result)
	}
	c.active, c.running, c.last, c.result, c.client, c.session, c.input, c.output = false, false, time.Time{}, nil, nil, nil, nil, nil
	c.mu.Unlock()
}

func NewSSHTransport(remote string, credentials *SSHCredentials, options *SSHOptions, extra ...int) (transport *sshTransport, err error) {
	if remote == "" {
		return nil, errors.New("ssh: invalid remote parameter")
	}
	if credentials == nil || credentials.Username == "" || (credentials.Password == "" && credentials.Key == "") {
		return nil, errors.New("ssh: invalid credentials")
	}
	if options == nil {
		options = &SSHOptions{Mode: TEXT}
	}
	if options.SubSystem != "" && options.SubSystem != "netconf" {
		return nil, errors.New("ssh: invalid subsystem")
	}
	if _, err := netip.ParseAddrPort(remote); err != nil {
		if options.SubSystem == "netconf" {
			remote += ":830"

		} else {
			remote += ":22"
		}
	}
	switch options.SubSystem {
	case "":
		if options.Marker == "" {
			options.Marker = `^[^\$]*[\$]`
		}
		if options.Mode == XML && options.Filter == "" {
			options.Filter = `^([^<]|$)`
		}

	case "netconf":
		options.Mode = XML
		if options.Marker == "" {
			options.Marker = `^\]\]>\]\]>`
		}
	}
	if options.Marker == "" {
		return nil, errors.New("ssh: invalid marker")
	}
	if options.Mode != TEXT && options.Mode != JSON && options.Mode != XML {
		return nil, errors.New("ssh: invalid mode")
	}

	key := remote + credentials.Username + credentials.Password + credentials.Key + options.Mode + options.SubSystem + options.Marker + options.Filter
	sshLock.Lock()
	defer sshLock.Unlock()
	if transport = sshTransports[key]; transport != nil {
		return
	}
	auth := []ssh.AuthMethod{}
	if credentials.Key != "" {
		if private, err := os.ReadFile(credentials.Key); err != nil {
			return nil, ustr.Wrap(err, "ssh")

		} else if signer, err := ssh.ParsePrivateKey(private); err != nil {
			return nil, ustr.Wrap(err, "ssh")

		} else {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	if credentials.Password != "" {
		auth = append(auth, ssh.Password(credentials.Password))
	}

	idle := sshIdleTimeout
	if len(extra) >= 2 && extra[1] != 0 {
		idle = time.Duration(extra[1]) * time.Second
	}
	transport = &sshTransport{
		remote:  remote,
		idle:    idle,
		options: options,
		config: &ssh.ClientConfig{
			User:            credentials.Username,
			Timeout:         sshConnectTimeout,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth:            auth,
		},
	}

	highest := sshMaxConnections
	if len(extra) >= 1 && extra[0] != 0 {
		highest = extra[0]
	}
	transport.connections = make([]*sshConnection, min(sshMaxConnections, max(1, highest)))
	sshTransports[key] = transport
	return
}

func (t *sshTransport) Run(command string, timeout time.Duration, cache ...bool) (result any, err error) {
	var (
		start = time.Now()
		conn  *sshConnection
		ckey  string
	)

	if len(cache) > 0 && cache[0] {
		hash := md5.Sum([]byte(t.remote + t.options.Mode + t.options.SubSystem + t.options.Marker + t.options.Filter + command))
		ckey = "/tmp/_" + ustr.Hex(hash[:]) + ".json"
		if content, err := os.ReadFile(ckey); err == nil {
			if json.Unmarshal(content, &result) == nil {
				return result, nil
			}
		}
	}
	if command == "" {
		return nil, errors.New("ssh: invalid or missing parameter")
	}
	if timeout <= 0 {
		timeout = sshExecTimeout
	}

	for {
		t.Lock()
		for index, value := range t.connections {
			if value == nil || !value.active {
				conn = value
				if conn == nil {
					conn = &sshConnection{}
					t.connections[index] = conn

				}
				conn.active, conn.last = true, time.Now()
				break
			}
		}
		t.Unlock()
		if conn == nil {
			if time.Since(start) >= timeout/2 {
				return nil, errors.New("ssh: max connections reached")
			}
			time.Sleep(time.Second)

		} else {
			break
		}
	}

	if conn.session == nil {
		if conn.client, err = ssh.Dial("tcp", t.remote, t.config); err != nil {
			conn.Reset()
			return nil, ustr.Wrap(err, "ssh")
		}
		if conn.session, err = conn.client.NewSession(); err != nil {
			conn.Reset()
			return nil, ustr.Wrap(err, "ssh")
		}
		if conn.input, err = conn.session.StdinPipe(); err != nil {
			conn.Reset()
			return nil, ustr.Wrap(err, "ssh")
		}
		if conn.output, err = conn.session.StdoutPipe(); err != nil {
			conn.Reset()
			return nil, ustr.Wrap(err, "ssh")
		}
		if t.options.SubSystem != "" {
			if err = conn.session.RequestSubsystem(t.options.SubSystem); err != nil {
				conn.Reset()
				return nil, ustr.Wrap(err, "ssh")
			}

		} else if err = conn.session.Shell(); err != nil {
			conn.Reset()
			return nil, ustr.Wrap(err, "ssh")
		}

		go func() {
			begin, data, lines, mmatcher, fmatcher := 0, make([]byte, 64<<10), make([]string, 0, 4<<10), rcache.Get(t.options.Marker), rcache.Get(t.options.Filter)
			for {
				if conn.output == nil {
					break
				}
				read, err := conn.output.Read(data[begin:])
				if read > 0 {
					read += begin
					begin = 0
					index := 0
					for index < read {
						line, complete := "", false
						if end := bytes.Index(data[index:read], []byte("\n")); end >= 0 {
							line, complete = strings.TrimRight(string(data[index:index+end]), "\r"), true
							index += end + 1

						} else {
							line, index = string(data[index:read]), read
							begin = len(line)
							copy(data, line)
						}
						sline := strings.TrimSpace(line)
						if mmatcher.MatchString(sline) {
							conn.mu.Lock()
							if conn.result == nil {
								conn.result = make(chan []string)
							}
							if conn.result != nil && conn.running {
								conn.result <- lines
							}
							conn.mu.Unlock()
							lines, begin = lines[:0], 0
							continue
						}
						if complete {
							if t.options.Filter != "" && fmatcher.MatchString(sline) {
								continue
							}
							lines = append(lines, line)
						}
					}
				}
				if err != nil {
					break
				}
			}
		}()
	}

	for {
		if time.Since(start) >= timeout {
			conn.Reset()
			return nil, errors.New("ssh: readyness timeout")
		}
		conn.mu.Lock()
		if conn.result != nil {
			conn.running = true
			conn.mu.Unlock()
			break
		}
		conn.mu.Unlock()
		time.Sleep(time.Second / 6)
	}

	command = strings.TrimSpace(command)
	switch t.options.SubSystem {
	case "":
		switch t.options.Mode {
		case JSON:
			if !strings.Contains(command, "display json") {
				command += "|display json|no-more"
			}

		case XML:
			if !strings.Contains(command, "display xml") {
				command += "|display xml|no-more"
			}
		}

	case "netconf":
		if !strings.HasPrefix(command, "<rpc>") || !strings.HasSuffix(command, "</rpc>") {
			command = "<rpc>" + command + "</rpc>"
		}
	}

	if _, err = conn.input.Write([]byte(command + "\n")); err != nil {
		conn.Reset()
		return nil, ustr.Wrap(err, "ssh")
	}
	select {
	case value := <-conn.result:
		switch t.options.Mode {
		case TEXT:
			result = value

		case JSON:
			for index, line := range value {
				if line != "" && line[0] == '{' {
					value = value[index:]
					break
				}
			}
			result = parseJSON(strings.Join(value, ""))

		case XML:
			for index, line := range value {
				if line != "" && line[0] == '<' {
					value = value[index:]
					break
				}
			}
			result = parseXML(strings.Join(value, "\n"))
		}

	case <-time.After(timeout - time.Since(start)):
		err = errors.New("ssh: execution timeout")
		conn.Reset()
	}
	conn.mu.Lock()
	conn.active, conn.running = false, false
	conn.mu.Unlock()
	if ckey != "" {
		if handle, err := os.OpenFile(ckey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644); err == nil {
			encoder := json.NewEncoder(handle)
			encoder.SetEscapeHTML(false)
			encoder.Encode(result)
			handle.Close()
		}
	}
	return
}

func (t *sshTransport) Map(command string, timeout time.Duration, mapping map[string]string, cache ...bool) (result map[string]any, err error) {
	if run, err := t.Run(command, timeout, cache...); err != nil {
		return nil, err

	} else {
		return Mapper(nil, run, mapping), nil
	}
}
