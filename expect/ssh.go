package expect

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
	"github.com/pyke369/golang-support/uuid"
	"golang.org/x/crypto/ssh"
)

type SSHCredentials struct {
	Username string
	Password string
	Key      string
}

type SSHOptions struct {
	ConnectTimeout time.Duration
	ExecTimeout    time.Duration
	IdleTimeout    time.Duration
	Mode           string
	SubSystem      string
	Pty            bool
	Prompt         string
	Filter         string
	Mock           func(string, any) []string
	Rewrite        func([]string, any) []string
}

type SSHConn struct {
	remote  string
	closed  atomic.Bool
	last    int64
	config  *ssh.ClientConfig
	options *SSHOptions
	client  *ssh.Client
	session *ssh.Session
	input   io.WriteCloser
	output  io.Reader
}

func NewSSHConn(remote string, credentials *SSHCredentials, options *SSHOptions) (conn *SSHConn, err error) {
	if remote == "" {
		return nil, errors.New("ssh: invalid remote")
	}
	if credentials == nil || credentials.Username == "" || (credentials.Password == "" && credentials.Key == "") {
		return nil, errors.New("ssh: invalid credentials")
	}
	if options == nil {
		options = &SSHOptions{Mode: TEXT}
	}
	if options.Mode == "" {
		options.Mode = TEXT
	}
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = 7 * time.Second
	}
	options.ConnectTimeout = min(15*time.Second, max(time.Second, options.ConnectTimeout))
	if options.ExecTimeout == 0 {
		options.ExecTimeout = 30 * time.Second
	}
	options.ExecTimeout = min(2*time.Minute, max(5*time.Second, options.ExecTimeout))
	if options.IdleTimeout == 0 {
		options.IdleTimeout = time.Minute
	}
	if options.IdleTimeout != 0 {
		options.IdleTimeout = min(time.Minute, max(options.ExecTimeout, options.IdleTimeout))
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
		if options.Prompt == "" {
			options.Prompt = `^[^\$#]*[\$#]`
		}
		if options.Mode == XML && options.Filter == "" {
			options.Filter = `^([^<]|$)`
		}

	case "netconf":
		options.Mode = XML
		if options.Prompt == "" {
			options.Prompt = `^\]\]>\]\]>`
		}
	}
	if options.Prompt == "" {
		return nil, errors.New("ssh: invalid prompt")
	}
	if options.Mode != TEXT && options.Mode != JSON && options.Mode != XML {
		return nil, errors.New("ssh: invalid mode")
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

	return &SSHConn{
		remote:  remote,
		options: options,
		config: &ssh.ClientConfig{
			User:            credentials.Username,
			Timeout:         options.ConnectTimeout,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth:            auth,
		},
	}, nil
}

func (c *SSHConn) Close() {
	if c.closed.Load() {
		return
	}
	c.closed.Store(true)
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
	if c.input != nil {
		c.input.Close()
	}
}

func (c *SSHConn) readlines(timeout time.Duration, prompt, filter string) (lines []string, err error) {
	queue := make(chan []string)

	go func() {
		defer func() {
			recover()
		}()

		data, offset, prompt, filter, lines := make([]byte, 64<<10), 0, rcache.Get(prompt), rcache.Get(filter), []string{}
	done:
		for {
			n, err := c.output.Read(data[offset:])
			if err != nil {
				return
			}
			n += offset

			loffset := 0
			for {
				if lindex := bytes.IndexAny(data[loffset:n], "\n"); lindex >= 0 {
					line := bytes.TrimSpace(data[loffset : loffset+lindex])
					loffset += lindex + 1
					if prompt.Match(line) {
						break done
					}
					if c.options.Filter != "" && filter.Match(line) {
						continue
					}
					lines = append(lines, string(line))
					continue
				}

				offset = 0
				if loffset < n {
					copy(data, data[loffset:n])
					offset = n - loffset
					if prompt.Match(bytes.TrimSpace(data[:offset])) {
						break done
					}
				}
				break
			}
		}
		queue <- lines
	}()

	select {
	case lines = <-queue:

	case <-time.After(timeout):
		c.Close()
		err = os.ErrDeadlineExceeded
	}
	close(queue)

	return
}

func (c *SSHConn) Run(command string, extra ...map[string]any) (result any, err error) {
	if command == "" {
		return nil, errors.New("ssh: invalid or missing parameter")
	}
	if c.closed.Load() {
		return nil, errors.New("ssh: connection closed")
	}

	var (
		ctx   any
		trace *os.File
	)

	timeout, prompt, filter, mock, rewrite, raw, empty := c.options.ExecTimeout, c.options.Prompt, c.options.Filter, c.options.Mock, c.options.Rewrite, false, false
	if len(extra) > 0 {
		if value, ok := extra[0]["timeout"].(time.Duration); ok {
			timeout = value
		}
		if value, ok := extra[0]["prompt"].(string); ok && value != "" {
			prompt = value
		}
		if value, ok := extra[0]["filter"].(string); ok {
			filter = value
		}
		if value, exists := extra[0]["context"]; exists {
			ctx = value
		}
		if value, ok := extra[0]["mock"].(func(string, any) []string); ok {
			mock = value
		}
		if value, ok := extra[0]["rewrite"].(func([]string, any) []string); ok {
			rewrite = value
		}
		if value, ok := extra[0]["raw"].(bool); ok {
			raw = value
		}
		if value, ok := extra[0]["empty"].(bool); ok {
			empty = value
		}
		if value, ok := extra[0]["trace"].(*os.File); ok {
			trace = value
		}
	}
	timeout = min(5*time.Minute, max(5*time.Second, timeout))

	if c.session == nil && mock == nil {
		start := time.Now()
		if c.client, err = ssh.Dial("tcp", c.remote, c.config); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}
		if c.session, err = c.client.NewSession(); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}

		if c.input, err = c.session.StdinPipe(); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}
		if c.output, err = c.session.StdoutPipe(); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}
		if c.options.SubSystem != "" {
			if err = c.session.RequestSubsystem(c.options.SubSystem); err != nil {
				c.Close()
				return nil, ustr.Wrap(err, "ssh")
			}

		} else {
			if c.options.Pty {
				if err = c.session.RequestPty("xterm", 40, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
					c.Close()
					return nil, ustr.Wrap(err, "ssh")
				}
			}
			if err = c.session.Shell(); err != nil {
				c.Close()
				return nil, ustr.Wrap(err, "ssh")
			}
		}

		if _, err := c.readlines(c.options.ConnectTimeout-time.Since(start), prompt, filter); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}

		if c.options.IdleTimeout != 0 {
			c.last = time.Now().Unix()
			go func(c *SSHConn) {
				for {
					if c.closed.Load() {
						break
					}
					if time.Now().Unix()-atomic.LoadInt64(&c.last) >= int64(c.options.IdleTimeout/time.Second) {
						c.Close()
						break
					}
					time.Sleep(time.Second)
				}
			}(c)
		}
	}

	command = strings.TrimSpace(command)
	suffix := ""
	switch c.options.SubSystem {
	case "":
		switch c.options.Mode {
		case JSON:
			if !strings.Contains(command, "display json") {
				command += "|display json |no-more"
			}

		case XML:
			if !strings.Contains(command, "display xml") {
				command += "|display xml |no-more"
			}
		}

	case "netconf":
		if !strings.HasPrefix(command, "<rpc") {
			id := uuid.New()
			command = `<rpc message-id="` + id.String() + `">` + "\n" + command
		}
		if !strings.HasSuffix(command, "</rpc>") {
			command += "\n</rpc>"
		}
		suffix = "\n]]>]]>"
	}
	if trace != nil {
		trace.WriteString(">  " + strings.Join(strings.Split(command, "\n"), "\n>  ") + "\n\n")
	}

	var lines []string

	if mock != nil {
		lines = mock(command+suffix+"\n", ctx)

	} else {
		atomic.StoreInt64(&c.last, time.Now().Unix())
		if _, err = c.input.Write([]byte(command + suffix + "\n")); err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}

		lines, err = c.readlines(timeout, prompt, filter)
		if err != nil {
			c.Close()
			return nil, ustr.Wrap(err, "ssh")
		}
	}

	if raw {
		if rewrite != nil {
			lines = rewrite(lines, ctx)
		}
		if trace != nil {
			trace.WriteString("<  " + strings.Join(lines, "\n<  ") + "\n\n")
		}
		result = lines

	} else {
		switch c.options.Mode {
		case TEXT:
			if rewrite != nil {
				lines = rewrite(lines, ctx)
			}
			if trace != nil {
				trace.WriteString("<  " + strings.Join(lines, "\n<  ") + "\n\n")
			}
			result = lines

		case JSON:
			if rewrite != nil {
				lines = rewrite(lines, ctx)
			}
			for index, line := range lines {
				if line != "" && line[0] == '{' {
					lines = lines[index:]
					break
				}
			}
			result = ParseJSON(strings.Join(lines, ""))

		case XML:
			if rewrite != nil {
				lines = rewrite(lines, ctx)
			}
			if trace != nil {
				trace.WriteString("<  " + strings.Join(lines, "\n<  ") + "\n\n")
			}
			for index, line := range lines {
				if line != "" && line[0] == '<' {
					lines = lines[index:]
					break
				}
			}
			result = ParseXML(lines, empty)
		}
	}
	atomic.StoreInt64(&c.last, time.Now().Unix())

	return
}

func (c *SSHConn) Map(command string, mapping map[string]string, extra ...map[string]any) (result map[string]any, err error) {
	run, err := c.Run(command, extra...)
	if err != nil {
		return nil, err
	}

	return Mapper(nil, run, mapping), nil
}
