package expect

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
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
	Mode           string
	PseudoTerminal bool
	SubSystem      string
	Marker         string
	Filter         string
	Trace          bool
}
type sshConnection struct {
	sync.Mutex
	active  bool
	running bool
	last    time.Time
	client  *ssh.Client
	session *ssh.Session
	input   io.WriteCloser
	output  io.Reader
	result  chan ([]string)
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
	c.Lock()
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
	c.Unlock()
}

func NewSSHTransport(remote string, credentials *SSHCredentials, options *SSHOptions, extra ...int) (transport *sshTransport, err error) {
	if remote == "" {
		return nil, fmt.Errorf("ssh: invalid remote parameter")
	}
	if credentials == nil || credentials.Username == "" || (credentials.Password == "" && credentials.Key == "") {
		return nil, fmt.Errorf("ssh: invalid credentials")
	}
	if options == nil {
		options = &SSHOptions{Mode: TEXT, PseudoTerminal: true, Marker: `^[^\$]*\$`}
	}
	if options.Mode != TEXT && options.Mode != JSON && options.Mode != XML {
		return nil, fmt.Errorf("ssh: invalid mode")
	}
	if _, _, err := net.SplitHostPort(remote); err != nil {
		if options.Mode == XML {
			remote += ":830"
		} else {
			remote += ":22"
		}
	}
	switch options.Mode {
	case JSON:
		if options.Marker == "" {
			options.Marker = `^\{(master|backup|linecard|primary|secondary)(:(node)?\d+)?\}`
		}
		if options.Filter == "" {
			options.Filter = `^(([^@]+@)?[^>]+>|$)`
		}
	case XML:
		if options.Marker == "" {
			options.Marker = `^\]\]>\]\]>`
		}
		if options.Filter == "" {
			options.Filter = `^$`
		}
	}
	if options.Marker == "" {
		return nil, fmt.Errorf("ssh: invalid marker")
	}

	key := fmt.Sprintf("%s%v%v", remote, credentials, options)
	sshLock.Lock()
	defer sshLock.Unlock()
	if transport = sshTransports[key]; transport != nil {
		return
	}
	auth := []ssh.AuthMethod{}
	if credentials.Key != "" {
		if private, err := os.ReadFile(credentials.Key); err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		} else if signer, err := ssh.ParsePrivateKey(private); err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
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

	max := sshMaxConnections
	if len(extra) >= 1 && extra[0] != 0 {
		max = extra[0]
	}
	transport.connections = make([]*sshConnection, int(math.Min(sshMaxConnections, math.Max(1, float64(max)))))
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
		ckey = fmt.Sprintf("/tmp/_%x.json", md5.Sum([]byte(fmt.Sprintf("%s%v%s", t.remote, t.options, command))))
		if content, err := os.ReadFile(ckey); err == nil {
			if json.Unmarshal(content, &result) == nil {
				return result, nil
			}
		}
	}
	if command == "" {
		return nil, fmt.Errorf("ssh: invalid or missing parameter")
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
				return nil, fmt.Errorf("ssh: max connections reached")
			}
			time.Sleep(time.Second)
		} else {
			break
		}
	}

	if conn.session == nil {
		if conn.client, err = ssh.Dial("tcp", t.remote, t.config); err != nil {
			conn.Reset()
			return nil, fmt.Errorf("ssh: %w", err)
		}
		if conn.session, err = conn.client.NewSession(); err != nil {
			conn.Reset()
			return nil, fmt.Errorf("ssh: %w", err)
		}
		if t.options.PseudoTerminal {
			if err = conn.session.RequestPty("xterm", 0, 0, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
				conn.Reset()
				return nil, fmt.Errorf("ssh: %w", err)
			}
		}
		if conn.input, err = conn.session.StdinPipe(); err != nil {
			conn.Reset()
			return nil, fmt.Errorf("ssh: %w", err)
		}
		if conn.output, err = conn.session.StdoutPipe(); err != nil {
			conn.Reset()
			return nil, fmt.Errorf("ssh: %w", err)
		}
		if t.options.SubSystem != "" {
			if err = conn.session.RequestSubsystem(t.options.SubSystem); err != nil {
				conn.Reset()
				return nil, fmt.Errorf("ssh: %w", err)
			}
		} else if err = conn.session.Shell(); err != nil {
			conn.Reset()
			return nil, fmt.Errorf("ssh: %w", err)
		}
		go func() {
			buffer, lines, mmatcher, fmatcher := make([]byte, 64<<10), make([]string, 0, 4<<10), rcache.Get(t.options.Marker), rcache.Get(t.options.Filter)
			for {
				if conn.output == nil {
					break
				}
				read, err := conn.output.Read(buffer)
				if read >= 0 {
					for _, line := range bytes.Split(buffer[:read], []byte("\n")) {
						if t.options.Trace {
							fmt.Fprintf(os.Stderr, "< %s\n", bytes.TrimRight(line, "\r\n"))
						}
						sline := bytes.TrimSpace(line)
						if mmatcher.Match(sline) {
							conn.Lock()
							if conn.result == nil {
								conn.result = make(chan []string)
							}
							if conn.result != nil && conn.running {
								conn.result <- lines
							}
							conn.Unlock()
							lines = lines[:0]
							continue
						}
						if t.options.Filter != "" && fmatcher.Match(sline) {
							continue
						}
						lines = append(lines, string(line))
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
			return nil, fmt.Errorf("ssh: readyness timeout")
		}
		conn.Lock()
		if conn.result != nil {
			conn.running = true
			conn.Unlock()
			break
		}
		conn.Unlock()
		time.Sleep(time.Second / 6)
	}

	command = strings.TrimSpace(command)
	switch t.options.Mode {
	case JSON:
		if !strings.Contains(command, "display json") {
			command += "|display json|no-more"
		}
	case XML:
		if !strings.HasPrefix(command, "<rpc>") || !strings.HasSuffix(command, "</rpc>") {
			command = "<rpc>" + command + "</rpc>"
		}
	}
	if _, err = fmt.Fprintf(conn.input, command+"\n"); err != nil {
		conn.Reset()
		return nil, fmt.Errorf("ssh: %w", err)
	}
	if t.options.Trace {
		fmt.Fprintf(os.Stderr, "> %s\n", command)
	}
	select {
	case value := <-conn.result:
		switch t.options.Mode {
		case TEXT:
			result = value

		case JSON:
			for index, line := range value {
				if len(line) != 0 && line[0] == '{' {
					value = value[index:]
					break
				}
			}
			result = parseJSON(strings.Join(value, ""))

		case XML:
			for index, line := range value {
				if len(line) != 0 && line[0] == '<' {
					value = value[index:]
					break
				}
			}
			result = parseXML(strings.Join(value, ""))
		}
	case <-time.After(timeout - time.Since(start)):
		err = fmt.Errorf("ssh: execution timeout")
		conn.Reset()
	}
	conn.Lock()
	conn.active, conn.running = false, false
	conn.Unlock()
	if ckey != "" {
		if content, err := json.Marshal(result); err == nil {
			os.WriteFile(ckey, content, 0644)
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
