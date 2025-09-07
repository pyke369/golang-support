package ubgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	l "github.com/pyke369/golang-support/listener"
	"github.com/pyke369/golang-support/ustr"

	"encoding/hex"
)

const (
	Receive = 1
	Send    = 1
)

type Group struct {
	name       string
	messages   chan *message
	mu         sync.RWMutex
	peers      map[string]*Peer
	processors map[*Processor]struct{}
}

type Speaker struct {
	name      string
	key       string
	local     *net.TCPAddr
	listener  *l.TCPListener
	mu        sync.RWMutex
	closed    bool
	templates map[*Template]struct{}
	peers     map[string]*Peer
}

type Template struct {
	name     string
	speaker  *Speaker
	localASN string
	peerASN  string
	options  map[string]any
	mu       sync.RWMutex
	removed  bool
	prefixes map[string]*net.IPNet
	peers    map[string]*Peer
}

type Peer struct {
	name             string
	key              string
	group            *Group
	speaker          *Speaker
	template         *Template
	remote           *net.TCPAddr
	localASN         int
	peerASN          int
	id               int
	pace             time.Duration
	connect          time.Duration
	last             time.Time
	established      time.Time
	sent             time.Time
	received         time.Time
	capabilities     map[int]Capability
	peerCapabilities map[int]Capability
	families         map[Family]struct{}
	peerFamilies     map[Family]struct{}
	multipath        map[Family]int
	peerMultipath    map[Family]int
	hold             time.Duration
	eor              bool
	peerHold         time.Duration
	peerASN4         int
	reason           map[string]any
	messages         chan *message
	mu               sync.RWMutex
	removed          bool
	enabled          bool
	state            string
	processors       map[*Processor]struct{}
	conn             net.Conn
	dmu              sync.Mutex
	data             []byte
}

type Processor struct {
	OnPeer    func(group *Group, speaker *Speaker, peer *Peer, reason map[string]any)
	OnState   func(group *Group, speaker *Speaker, peer *Peer, from, to string, reason map[string]any)
	OnUp      func(group *Group, speaker *Speaker, peer *Peer)
	OnDown    func(group *Group, speaker *Speaker, peer *Peer, reason map[string]any)
	OnMessage func(group *Group, speaker *Speaker, peer *Peer, direction, message string, payload []byte)
	OnUpdate  func(group *Group, speaker *Speaker, peer *Peer, update map[string]any)
	OnRefresh func(group *Group, speaker *Speaker, peer *Peer, family Family, enhanced int)
}

type message struct {
	event   string
	group   *Group
	speaker *Speaker
	peer    *Peer
	payload map[string]any
}

var (
	messages = make(chan *message, 64<<10)
	raw      = int32(0)
	mu       sync.RWMutex
	groups   = map[string]*Group{
		"default": &Group{
			name:       "default",
			peers:      map[string]*Peer{},
			processors: map[*Processor]struct{}{},
			messages:   make(chan *message, 64<<10),
		},
	}
	speakers   = map[string]*Speaker{}
	processors = map[*Processor]struct{}{}
)

func AddProcessor(processor *Processor) {
	mu.Lock()
	if processor != nil {
		if _, exists := processors[processor]; !exists {
			processors[processor] = struct{}{}
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, 1)
			}
		}
	}
	mu.Unlock()
}

func RemoveProcessor(processor *Processor) {
	mu.Lock()
	if processor != nil {
		if _, exists := processors[processor]; exists {
			delete(processors, processor)
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, -1)
			}
		}
	}
	mu.Unlock()
}

func Enable(enabled bool) {
	mu.RLock()
	for _, group := range groups {
		group.Enable(enabled)
	}
	mu.RUnlock()
}

func Update(update map[string]any) {
	mu.RLock()
	for _, group := range groups {
		group.Update(update)
	}
	mu.RUnlock()
}

func Groups() (list []*Group) {
	list = []*Group{}
	mu.RLock()
	for _, group := range groups {
		list = append(list, group)
	}
	mu.RUnlock()
	return
}

func Speakers() (list []*Speaker) {
	list = []*Speaker{}
	mu.RLock()
	for _, speaker := range speakers {
		list = append(list, speaker)
	}
	mu.RUnlock()
	return
}

func Peers() (peers []*Peer) {
	peers = []*Peer{}
	mu.RLock()
	for _, group := range groups {
		peers = append(peers, group.Peers()...)
	}
	mu.RUnlock()
	return nil
}

func init() {
	go dispatch("global", &mu, messages, processors)
	groups["default"].init()
}

func dispatch(category string, lock *sync.RWMutex, messages chan *message, processors map[*Processor]struct{}) {
	for {
		msg := <-messages
		if msg == nil {
			break
		}

		from, to, reason, direction, message, payload, update, family, enhanced := "", "", map[string]any{}, "", "", []byte{}, map[string]any{}, Family{}, 0
		switch msg.event {
		case "peer", "state":
			from, to, reason = j.String(msg.payload["from"]), j.String(msg.payload["to"]), j.Map(msg.payload["reason"])

		case "message":
			direction, message = j.String(msg.payload["direction"]), j.String(msg.payload["message"])
			if value, ok := msg.payload["payload"].([]byte); ok {
				payload = value
			}

		case "update":
			if value, ok := msg.payload["payload"].(map[string]any); ok {
				update = value
			}

		case "refresh":
			if value, ok := msg.payload["family"].(Family); ok {
				family = value
			}
			enhanced = int(j.Number(msg.payload["enhanced"]))
		}

		lock.RLock()
		for processor := range processors {
			switch msg.event {
			case "peer":
				if processor.OnPeer != nil {
					processor.OnPeer(msg.group, msg.speaker, msg.peer, reason)
				}

			case "state":
				if from != "" && to != "" {
					if processor.OnState != nil {
						processor.OnState(msg.group, msg.speaker, msg.peer, from, to, reason)
					}
					if processor.OnUp != nil && to == stateEstablished && from != stateEstablished {
						processor.OnUp(msg.group, msg.speaker, msg.peer)
					}
					if processor.OnDown != nil && to == stateIdle && from == stateEstablished {
						processor.OnDown(msg.group, msg.speaker, msg.peer, reason)
					}
				}

			case "message":
				if direction != "" && message != "" {
					if processor.OnMessage != nil {
						processor.OnMessage(msg.group, msg.speaker, msg.peer, direction, message, payload)
					}
				}

			case "update":
				if processor.OnUpdate != nil {
					processor.OnUpdate(msg.group, msg.speaker, msg.peer, update)
				}

			case "refresh":
				if processor.OnRefresh != nil {
					processor.OnRefresh(msg.group, msg.speaker, msg.peer, family, enhanced)
				}
			}
		}
		lock.RUnlock()
	}
}

func (g *Group) AddProcessor(processor *Processor) {
	g.mu.Lock()
	if processor != nil {
		if _, exists := g.processors[processor]; !exists {
			g.processors[processor] = struct{}{}
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, 1)
			}
		}
	}
	g.mu.Unlock()
}

func (g *Group) RemoveProcessor(processor *Processor) {
	g.mu.Lock()
	if processor != nil {
		if _, exists := g.processors[processor]; exists {
			delete(g.processors, processor)
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, -1)
			}
		}
	}
	g.mu.Unlock()
}

func (g *Group) Enable(enabled bool) {
	g.mu.RLock()
	for _, peer := range g.peers {
		peer.Enable(enabled)
	}
	g.mu.RUnlock()
}

func (g *Group) Update(update map[string]any) {
	g.mu.RLock()
	for _, peer := range g.peers {
		peer.Update(update)
	}
	g.mu.RUnlock()
}

func (g *Group) Name() string {
	return g.name
}

func (g *Group) Peers() (peers []*Peer) {
	peers = []*Peer{}
	g.mu.RLock()
	for _, peer := range g.peers {
		peers = append(peers, peer)
	}
	g.mu.RUnlock()
	return
}

func (g *Group) init() {
	go dispatch("group", &g.mu, g.messages, g.processors)
}

func NewSpeaker(local string, options ...map[string]any) (speaker *Speaker, err error) {
	host, port := local, "0"
	if value1, value2, err := net.SplitHostPort(local); err == nil {
		host, port = value1, value2
	}
	address, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	key := address.String()
	if speaker, exists := speakers[key]; exists {
		return speaker, nil
	}
	address, _ = net.ResolveTCPAddr("tcp", net.JoinHostPort(host, "0"))
	speaker = &Speaker{
		key:       key,
		local:     address,
		templates: map[*Template]struct{}{},
		peers:     map[string]*Peer{},
	}
	if len(options) != 0 {
		speaker.name = strings.TrimSpace(strings.ToLower(j.String(options[0]["name"])))
	}
	if port != "0" {
		speaker.listener, err = l.NewTCPListener("tcp", net.JoinHostPort(host, port), &l.TCPOptions{ReusePort: true})
		if err != nil {
			return nil, err
		}
		go func(s *Speaker) {
			for {
				remote, err := s.listener.Accept()
				if err != nil {
					break
				}
				go func(remote net.Conn) {
					address, reason := remote.RemoteAddr().String(), ""
					if value, _, err := net.SplitHostPort(address); err == nil {
						address = value
					}
					if address := net.ParseIP(address); address != nil {
						var selected *Template

						s.mu.Lock()
						for template := range s.templates {
							template.mu.RLock()
							for _, prefix := range template.prefixes {
								if prefix.Contains(address) {
									selected = template
									break
								}
							}
							template.mu.RUnlock()
						}
						s.mu.Unlock()
						if selected != nil {
							if peer, err := s.AddPeer(remote.RemoteAddr().String(), selected.localASN, selected.peerASN, selected.options); err == nil {
								peer.template, peer.conn = selected, remote
								selected.mu.Lock()
								selected.peers[peer.key] = peer
								selected.mu.Unlock()
								peer.Enable(true)
								msg := &message{"peer", peer.group, speaker, peer, nil}
								select {
								case peer.group.messages <- msg:
									select {
									case messages <- msg:

									default:
									}

								default:
								}
								return

							} else {
								reason = err.Error()
							}

						} else {
							reason = "unauthorized peer " + address.String()
						}
					}
					messages <- &message{"peer", nil, speaker, nil, map[string]any{"reason": map[string]any{"reason": reason}}}
					remote.Close()
				}(remote)
			}
		}(speaker)
	}
	speakers[speaker.key] = speaker
	return
}

func (s *Speaker) AddTemplate(remotes []string, localASN, peerASN string, options ...map[string]any) (template *Template, err error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, errors.New("closed speaker")
	}
	if s.listener == nil {
		s.mu.RUnlock()
		return nil, errors.New("non-listening speaker")
	}
	s.mu.RUnlock()

	template = &Template{
		speaker:  s,
		localASN: localASN,
		peerASN:  peerASN,
		options:  map[string]any{},
		prefixes: map[string]*net.IPNet{},
		peers:    map[string]*Peer{},
	}
	for _, remote := range remotes {
		if _, prefix, err := net.ParseCIDR(remote); err == nil {
			template.prefixes[prefix.String()] = prefix
		}
	}
	if len(template.prefixes) == 0 {
		return nil, errors.New("no valid prefix")
	}
	if len(options) != 0 {
		template.name = strings.TrimSpace(strings.ToLower(j.String(options[0]["name"])))
		delete(options[0], "name")
		delete(options[0], "enabled")
		template.options = options[0]
	}
	s.mu.Lock()
	s.templates[template] = struct{}{}
	s.mu.Unlock()
	return
}

func (s *Speaker) AddPeer(remote, localASN, peerASN string, options ...map[string]any) (peer *Peer, err error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, errors.New("closed speaker")
	}
	s.mu.RUnlock()
	mu.RLock()
	peer = &Peer{
		speaker:          s,
		group:            groups["default"],
		pace:             5 * time.Second,
		connect:          5 * time.Second,
		hold:             90 * time.Second,
		state:            stateIdle,
		data:             make([]byte, 64<<10),
		processors:       map[*Processor]struct{}{},
		messages:         make(chan *message, 64<<10),
		capabilities:     map[int]Capability{},
		peerCapabilities: map[int]Capability{},
		families:         map[Family]struct{}{ipv4Unicast: struct{}{}},
		peerFamilies:     map[Family]struct{}{},
		multipath:        map[Family]int{},
		peerMultipath:    map[Family]int{},
	}
	mu.RUnlock()
	if value := peer.speaker.local.IP.To4(); value != nil {
		peer.id = int(binary.BigEndian.Uint32(value))

	} else if value := peer.speaker.local.IP.To16(); value != nil {
		peer.id = int(binary.BigEndian.Uint32(value[12:]))
	}
	if _, _, err := net.SplitHostPort(remote); err != nil {
		remote += ":179"
	}
	if peer.remote, err = net.ResolveTCPAddr("tcp", remote); err != nil {
		return nil, ustr.Wrap(err, "invalid peer address "+remote)
	}
	if peer.localASN, err = strconv.Atoi(strings.TrimPrefix(localASN, "AS")); err != nil || peer.localASN <= 0 || peer.localASN >= (1<<32) {
		return nil, errors.New("invalid local ASN " + localASN)
	}
	if peer.peerASN, err = strconv.Atoi(strings.TrimPrefix(peerASN, "AS")); err != nil || peer.peerASN <= 0 || peer.peerASN >= (1<<32) {
		return nil, errors.New("invalid peer ASN " + peerASN)
	}

	peer.key = s.local.String() + "|" + localASN + "|" + peer.remote.String() + "|" + peerASN
	s.mu.Lock()
	if entry := s.peers[peer.key]; entry != nil {
		peer = entry
		s.mu.Unlock()
		return
	}
	s.peers[peer.key] = peer
	s.mu.Unlock()

	if len(options) > 0 {
		peer.name = strings.TrimSpace(strings.ToLower(j.String(options[0]["name"])))
		if value := strings.ToLower(strings.TrimSpace(j.String(options[0]["group"]))); value != "default" && value != "" {
			mu.Lock()
			if _, exists := groups[value]; !exists {
				groups[value] = &Group{
					name:       value,
					peers:      map[string]*Peer{},
					processors: map[*Processor]struct{}{},
					messages:   make(chan *message, 64<<10),
				}
				groups[value].init()
			}
			peer.group = groups[value]
			mu.Unlock()
		}
		if value := int(j.Number(options[0]["id"])); value != 0 {
			peer.id = value
		}
		if value := int(j.Number(options[0]["idle"])); value >= 1 && value <= 15 {
			peer.pace = time.Duration(value) * time.Second
		}
		if value := int(j.Number(options[0]["connect"])); value >= 1 && value <= 15 {
			peer.connect = time.Duration(value) * time.Second
		}
		if value := int(j.Number(options[0]["hold"])); value >= 3 {
			peer.hold = time.Duration(value) * time.Second
		}
		peer.eor = j.Boolean(options[0]["eor"])
		peer.enabled = j.Boolean(options[0]["enabled"])
		flushed := false
		if value, ok := options[0]["capabilities"].([]Capability); ok {
			for _, capability := range value {
				if capability.Valid() {
					switch capability.Code {
					case capabilities["multi-protocol"]:
						if len(capability.Value) == 4 {
							if !flushed {
								peer.families = map[Family]struct{}{}
								flushed = true
							}
							family := Family{int(binary.BigEndian.Uint16(capability.Value)), int(binary.BigEndian.Uint16(capability.Value[2:]))}
							if family.Valid() {
								peer.families[family] = struct{}{}
							}
						}

					case capabilities["extended-message"], capabilities["asn4"]:

					default:
						peer.capabilities[capability.Code] = capability
					}
				}
			}
		}
		if processor, ok := options[0]["processor"].(*Processor); ok {
			peer.AddProcessor(processor)
		}
	}

	peer.group.mu.Lock()
	peer.group.peers[peer.key] = peer
	peer.group.mu.Unlock()
	peer.init()

	return
}

func (s *Speaker) Close() {
	peers := []*Peer{}
	s.mu.Lock()
	if !s.closed {
		if s.listener != nil {
			s.listener.Close()
		}
		s.closed = true
		for _, peer := range s.peers {
			peers = append(peers, peer)
		}
	}
	s.mu.Unlock()
	for _, peer := range peers {
		peer.Remove()
	}
	mu.Lock()
	delete(speakers, s.key)
	mu.Unlock()
}

func (s *Speaker) Name() string {
	return s.name
}

func (s *Speaker) Templates() (templates []*Template) {
	templates = []*Template{}
	s.mu.RLock()
	for template := range s.templates {
		templates = append(templates, template)
	}
	s.mu.RUnlock()
	return
}

func (s *Speaker) Peers() (peers []*Peer) {
	peers = []*Peer{}
	s.mu.RLock()
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.mu.RUnlock()
	return
}

func (t *Template) AddPrefix(prefix string) {
	if _, prefix, err := net.ParseCIDR(prefix); err == nil {
		t.mu.Lock()
		if !t.removed {
			t.prefixes[prefix.String()] = prefix
		}
		t.mu.Unlock()
	}
}

func (t *Template) RemovePrefix(prefix string) {
	modified, count := false, 0
	if _, prefix, err := net.ParseCIDR(prefix); err == nil {
		t.mu.Lock()
		if !t.removed {
			if _, exists := t.prefixes[prefix.String()]; exists {
				delete(t.prefixes, prefix.String())
				count = len(t.prefixes)
				modified = true
			}
		}
		t.mu.Unlock()
		if modified {
			if count == 0 {
				t.Remove()
				return
			}
			peers := []*Peer{}
			t.mu.RLock()
			for _, peer := range t.peers {
				address := peer.RemoteAddr()
				if value, _, err := net.SplitHostPort(address); err == nil {
					address = value
				}
				if address := net.ParseIP(address); address != nil {
					if prefix.Contains(address) {
						peers = append(peers, peer)
					}
				}
			}
			t.mu.RUnlock()
			for _, peer := range peers {
				peer.Remove()
			}
		}
	}
}

func (t *Template) Remove() {
	peers := []*Peer{}
	t.mu.Lock()
	if !t.removed {
		t.removed = true
		for _, peer := range t.peers {
			peers = append(peers, peer)
		}
	}
	t.mu.Unlock()
	for _, peer := range peers {
		peer.Remove()
	}
	t.speaker.mu.Lock()
	delete(t.speaker.templates, t)
	t.speaker.mu.Unlock()
}

func (t *Template) Name() string {
	return t.name
}

func (p *Peer) AddProcessor(processor *Processor) {
	p.mu.Lock()
	if processor != nil {
		if _, exists := p.processors[processor]; !exists {
			p.processors[processor] = struct{}{}
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, 1)
			}
		}
	}
	p.mu.Unlock()
}

func (p *Peer) RemoveProcessor(processor *Processor) {
	p.mu.Lock()
	if processor != nil {
		if _, exists := p.processors[processor]; exists {
			delete(p.processors, processor)
			if processor.OnMessage != nil {
				atomic.AddInt32(&raw, -1)
			}
		}
	}
	p.mu.Unlock()
}

func (p *Peer) Enable(enabled bool) {
	p.mu.Lock()
	if !p.removed {
		p.enabled = enabled
	}
	p.mu.Unlock()
}

func (p *Peer) Update(update map[string]any) {
	if p.State() != stateEstablished {
		return
	}

	_, em := p.PeerCapability("extended-message")
	if unreachable, exists := update["unreachable"].(map[string][]string); exists {
		for value, prefixes := range unreachable {
			if family := NewFamily(value); family.Valid() && p.LocalFamily(family) && p.PeerFamily(family) {
				multipath := p.LocalMultipath(family, Send) && p.PeerMultipath(family, Receive)
				if family == ipv4Unicast {
					data := []byte{0, 0}
					for _, prefix := range prefixes {
						value := EncodePrefix(prefix, family, multipath)
						if len(value) == 0 {
							return
						}
						if (em && len(data)+len(value)+2 >= (64<<10)-19) || (!em && len(data)+len(value)+2 > (4<<10)-19) {
							binary.BigEndian.PutUint16(data, uint16(len(data)-2))
							data = append(data, []byte{0, 0}...)
							if !p.send(messageUpdate, data) {
								return
							}
							data = []byte{0, 0}
						}
						data = append(data, value...)
					}
					if len(data) > 2 || len(prefixes) == 0 {
						binary.BigEndian.PutUint16(data, uint16(len(data)-2))
						data = append(data, []byte{0, 0}...)
						if !p.send(messageUpdate, data) {
							return
						}
					}

				} else {
					data, alength := []byte{0, 0, 0, 0, 0x90, byte(attributes["unreachable"]), 0, 0}, 3
					data = binary.BigEndian.AppendUint16(data, uint16(family[0]))
					data = append(data, byte(family[1]))
					for _, prefix := range prefixes {
						value := EncodePrefix(prefix, family, multipath)
						if len(value) == 0 {
							return
						}
						if (em && len(data)+len(value) >= (64<<10)-19) || (!em && len(data)+len(value) > (4<<10)-19) {
							binary.BigEndian.PutUint16(data[6:], uint16(alength))
							binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
							if !p.send(messageUpdate, data) {
								return
							}
							data, alength = []byte{0, 0, 0, 0, 0x90, byte(attributes["unreachable"]), 0, 0}, 3
							data = binary.BigEndian.AppendUint16(data, uint16(family[0]))
							data = append(data, byte(family[1]))
						}
						data = append(data, value...)
						alength += len(value)
					}
					if alength > 3 || len(prefixes) == 0 {
						binary.BigEndian.PutUint16(data[6:], uint16(alength))
						binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
						if !p.send(messageUpdate, data) {
							return
						}
					}
				}
			}
		}
	}

	if reachable, exists := update["reachable"].(map[string]map[string][]string); exists {
		attributes := map[string]any{}
		if value, exists := update["attributes"].(map[string]any); exists {
			attributes = value
		}
		if _, exists := attributes["origin"]; !exists {
			attributes["origin"] = "igp"
		}
		if _, exists := attributes["as-path"]; !exists {
			if p.localASN == p.peerASN {
				attributes["as-path"] = ""

			} else {
				attributes["as-path"] = strconv.Itoa(p.localASN)
			}
		}
		if p.localASN == p.peerASN {
			if _, exists := attributes["local-preference"]; !exists {
				attributes["local-preference"] = 100
			}
		}
		for value, prefixes := range reachable {
			if family := NewFamily(value); family.Valid() && p.LocalFamily(family) && p.PeerFamily(family) {
				multipath := p.LocalMultipath(family, Send) && p.PeerMultipath(family, Receive)
				for nexthop, prefixes := range prefixes {
					if family == ipv4Unicast {
						if strings.Contains(nexthop, "self") {
							nexthop = p.conn.LocalAddr().String()
							if host, _, err := net.SplitHostPort(nexthop); err == nil {
								nexthop = host
							}
						}
						attributes["next-hop"] = nexthop

					} else {
						delete(attributes, "next-hop")
					}
					data, value := []byte{0, 0, 0, 0}, p.encodeAttributes(attributes)
					if len(value) == 0 || (em && len(data)+len(value) >= (64<<10)-19) || (!em && len(data)+len(value) > (4<<10)-19) {
						return
					}
					data = append(data, value...)
					for _, prefix := range prefixes {
						if family == ipv4Unicast {
							binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
							value := EncodePrefix(prefix, family, multipath)
							if len(value) == 0 {
								return
							}
							if (em && len(data)+len(value)+2 >= (64<<10)-19) || (!em && len(data)+len(value)+2 > (4<<10)-19) {
								if !p.send(messageUpdate, data) {
									return
								}
								data = append([]byte{0, 0, 0, 0}, p.encodeAttributes(attributes)...)
								binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
							}
							data = append(data, value...)

						} else {
							// TODO encode prefixes as MP_REACH_NLRI
							binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
						}
					}
					if len(data) > 4 {
						if family != ipv4Unicast {
							binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
						}
						if !p.send(messageUpdate, data) {
							return
						}
					}
				}
			}
		}
	}
}

func (p *Peer) EOR(list ...[]Family) {
	families := p.LocalFamilies()
	if len(list) > 0 && len(list[0]) > 0 {
		families = list[0]
	}
	unreachable := map[string][]string{}
	for _, family := range families {
		if p.LocalFamily(family) && p.PeerFamily(family) {
			unreachable[family.String()] = []string{}
		}
	}
	if len(unreachable) != 0 {
		p.Update(map[string]any{"unreachable": unreachable})
	}
}

func (p *Peer) Refresh(family Family, enhanced ...int) {
	if p.State() != stateEstablished {
		return
	}
	code := 0
	if len(enhanced) > 0 {
		code = enhanced[0]
	}
	_, rr := p.PeerCapability("route-refresh")
	_, err := p.PeerCapability("enhanced-route-refresh")
	if (code == 0 && rr && p.PeerFamily(family)) || ((code == 1 || code == 2) && err && p.LocalFamily(family)) {
		p.send(messageRefresh, []byte{byte(family[0] >> 8), byte(family[0]), byte(code), byte(family[1])})
	}
}

func (p *Peer) Cease(subcode int, message string) {
	if p.State() != stateEstablished {
		return
	}
	if subcode < 1 || subcode > 10 {
		subcode = 2
	}
	p.notification(notificationCease, subcode, message)
}

func (p *Peer) Remove() {
	p.idle(true)
}

func (p *Peer) Group() *Group {
	return p.group
}

func (p *Peer) Speaker() *Speaker {
	return p.speaker
}

func (p *Peer) Template() *Template {
	return p.template
}

func (p *Peer) Name() string {
	return p.name
}

func (p *Peer) State() (state string) {
	p.mu.RLock()
	state = p.state
	p.mu.RUnlock()
	return
}

func (p *Peer) Duration() (duration time.Duration) {
	p.mu.RLock()
	if !p.removed && p.state == stateEstablished {
		duration = time.Since(p.established)
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) LocalAddr() (address string) {
	p.mu.RLock()
	if !p.removed && p.conn != nil {
		address = p.conn.LocalAddr().String()
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) RemoteAddr() (address string) {
	p.mu.RLock()
	if !p.removed && p.conn != nil {
		address = p.conn.RemoteAddr().String()
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) LocalASN() (asn int) {
	p.mu.RLock()
	asn = p.localASN
	p.mu.RUnlock()
	return
}

func (p *Peer) PeerASN() (asn int) {
	p.mu.RLock()
	asn = p.peerASN
	p.mu.RUnlock()
	return
}

func (p *Peer) LocalCapabilities() (list []Capability) {
	p.mu.RLock()
	list = append(list, []Capability{NewCapability("extended-message"), NewCapability("asn4(" + strconv.Itoa(p.localASN) + ")")}...)
	for _, capability := range p.capabilities {
		list = append(list, capability)
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) LocalCapability(in string) (capability Capability, exists bool) {
	capability, exists = p.capabilities[capabilities[in]]
	return
}

func (p *Peer) PeerCapabilities() (list []Capability) {
	p.mu.RLock()
	if p.state == stateEstablished {
		for _, capability := range p.peerCapabilities {
			list = append(list, capability)
		}
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) PeerCapability(in string) (capability Capability, exists bool) {
	capability, exists = p.peerCapabilities[capabilities[in]]
	return
}

func (p *Peer) LocalFamilies() (list []Family) {
	p.mu.RLock()
	for family := range p.families {
		list = append(list, family)
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) LocalFamily(family Family) (exists bool) {
	_, exists = p.families[family]
	return
}

func (p *Peer) PeerFamilies() (list []Family) {
	p.mu.RLock()
	if p.state == stateEstablished {
		for family := range p.peerFamilies {
			list = append(list, family)
		}
	}
	p.mu.RUnlock()
	return
}

func (p *Peer) PeerFamily(family Family) (exists bool) {
	_, exists = p.peerFamilies[family]
	return
}

func (p *Peer) LocalMultipath(family Family, direction int) (ok bool) {
	if !p.LocalFamily(family) || !p.PeerFamily(family) {
		return
	}
	p.mu.RLock()
	value, exists := p.multipath[family]
	p.mu.RUnlock()
	if exists {
		return direction&value == direction
	}
	if capability, ok := p.LocalCapability("add-path"); ok && capability.Valid() {
		for offset := 0; offset < len(capability.Value); offset += 4 {
			if family[0] != int(binary.BigEndian.Uint16(capability.Value[offset:])) || family[1] != int(capability.Value[offset+2]) {
				continue
			}
			p.mu.Lock()
			value := int(capability.Value[offset+3])
			p.multipath[family] = value
			p.mu.Unlock()
			return direction&value == direction
		}
	}
	return
}

func (p *Peer) PeerMultipath(family Family, direction int) (ok bool) {
	if !p.LocalFamily(family) || !p.PeerFamily(family) {
		return
	}
	p.mu.RLock()
	value, exists := p.peerMultipath[family]
	p.mu.RUnlock()
	if exists {
		return direction&value == direction
	}
	if capability, ok := p.PeerCapability("add-path"); ok && capability.Valid() {
		for offset := 0; offset < len(capability.Value); offset += 4 {
			if family[0] != int(binary.BigEndian.Uint16(capability.Value[offset:])) || family[1] != int(capability.Value[offset+2]) {
				continue
			}
			p.mu.Lock()
			value := int(capability.Value[offset+3])
			p.peerMultipath[family] = value
			p.mu.Unlock()
			return direction&value == direction
		}
	}
	return
}

//	O T P E 0 0 0 0 x x x x x x x x
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Attr. Flags  |Attr. Type Code|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (p *Peer) encodeAttributes(in map[string]any) (out []byte) {
	for attribute, value := range in {
		switch attribute {
		case "origin":
			origin := 0
			if value, ok := value.(string); ok {
				switch strings.ToLower(value) {
				case "egp":
					origin = 1

				case "incomplete":
					origin = 2
				}
			}
			out = append(out, []byte{0x40, byte(attributes["origin"]), 1, byte(origin)}...)

		case "as-path":

			// "origin":                  1,
			// "as-path":                 2,
			// "next-hop":                3,
			// "med":                     4,
			// "local-preference":        5,

			// map[string]interface {}{"as-path":"", "local-preference":100, "next-hop":"127.0.0.1", "origin":"igp"}
			// 00000000  40 01 01 00 40 02 00 40  05 04 00 00 00 64 40 03  |@...@..@.....d@.|
			// 00000010  04 7f 00 00 01                                    |.....|

			// map[string]interface {}{"as-path":"1234567 54321 28465", "local-preference":100, "next-hop":"127.0.0.1", "origin":"igp"}
			// 00000000  40 02 0e 02 03 00 12 d6  87 00 00 d4 31 00 00 6f  |@...........1..o|
			// 00000010  31 40 01 01 00 40 05 04  00 00 00 64 40 03 04 7f  |1@...@.....d@...|
			// 00000020  00 00 01                                          |...|

			out = append(out, []byte{0x40, byte(attributes["as-path"]), 0}...)
			if value, ok := value.(string); ok {
				path := []int{}
				for _, value := range strings.Fields(value) {
					if asn, err := strconv.Atoi(value); err == nil && asn != 0 {
						path = append(path, asn)
					}
				}
				if len(path) != 0 && len(path) <= 60 {
					offset := len(out) - 1
					out = append(out, []byte{2, byte(len(path))}...)
					if _, ok := p.PeerCapability("asn4"); ok {
						for _, asn := range path {
							out = binary.BigEndian.AppendUint32(out, uint32(asn))
						}
						out[offset] = byte(len(out) - offset - 1)

					} else {
						asn4 := false
						for _, asn := range path {
							if asn > 65536 {
								asn, asn4 = 23456, true
							}
							out = binary.BigEndian.AppendUint16(out, uint16(asn))
						}
						out[offset] = byte(len(out) - offset - 1)
						if asn4 {
							out = append(out, []byte{0xc0, byte(attributes["as4-path"]), 0, 2, byte(len(path))}...)
							offset = len(out) - 3
							for _, asn := range path {
								out = binary.BigEndian.AppendUint32(out, uint32(asn))
							}
							out[offset] = byte(len(out) - offset - 1)
						}
					}
				}
			}

		case "next-hop":
			if value, ok := value.(string); ok {
				if addr, err := netip.ParseAddr(value); err == nil && addr.Is4() {
					out = append(out, []byte{0x40, byte(attributes["next-hop"]), 4}...)
					out = append(out, addr.AsSlice()...)
				}
			}

		case "med":
			if value, ok := value.(int); ok {
				out = append(out, []byte{0x80, byte(attributes["med"]), 4}...)
				out = binary.BigEndian.AppendUint32(out, uint32(value))
			}

		case "local-preference":
			if value, ok := value.(int); ok {
				out = append(out, []byte{0x40, byte(attributes["local-preference"]), 4}...)
				out = binary.BigEndian.AppendUint32(out, uint32(value))
			}

		// TODO case "community":
		// TODO case "extended-community":
		// TODO case "large-community":
		// TODO case "attributes-set":

		default:
			// TODO if key is xHH HH -> map to number
			// TODO else try to find number in attributes[]
			// TODO check flag (optional, transitive, partial)
			// TODO chech value is xHH HH HH ... and decode
			// TODO layout attribute + use extended flag is len(value) > 255
		}
	}
	fmt.Printf("%#v\n%s\n", in, hex.Dump(out))
	return
}

func (p *Peer) decodeAttributes(in []byte) (out map[string]any, code int) {
	out = map[string]any{}
	for offset := 0; offset < len(in); {
		if offset > len(in)-3 {
			return out, 1
		}
		a := int(in[offset+1])
		if a == 0 || (a >= 11 && a <= 13) || (a >= 19 && a <= 21) || a == 28 || a == 30 || a == 31 || a == 129 || (a >= 241 && a <= 243) || a == 255 {
			return out, 1
		}
		flags, length, header := int(in[offset]), int(in[offset+2]), 3
		if flags&0x10 != 0 {
			if offset > len(in)-4 {
				return out, 5
			}
			length, header = int(binary.BigEndian.Uint16(in[offset+2:])), 4
		}

		if offset+header+length > len(in) {
			return out, 5
		}
		attribute := ""
		for key, value := range attributes {
			if value == a {
				attribute = key
				break
			}
		}
		if attribute == "" {
			attribute = strconv.Itoa(a)
		}

		optional, transitive, partial := flags&0x80 != 0, flags&0x40 != 0, flags&0x20 != 0
		if attribute == "unreachable" || attribute == "reachable" {
			if !optional || transitive {
				return out, 4
			}
			if (attribute == "unreachable" && length < 3) || (attribute == "reachable" && length < 5) {
				return out, 5
			}
			family := Family{int(binary.BigEndian.Uint16(in[offset+header:])), int(in[offset+header+2])}
			if !family.Valid() {
				return out, 9
			}

			switch attribute {
			case "unreachable":
				if _, exists := out[attribute]; !exists {
					out[attribute] = map[string][]string{}
				}
				if value, ok := out[attribute].(map[string][]string); ok {
					if _, exists := value[family.String()]; exists {
						return out, 1
					}
				}
				prefixes, code := DecodePrefixes(in[offset+header+3:offset+header+length], family, p.LocalMultipath(family, Receive) && p.PeerMultipath(family, Send))
				if code != 0 {
					return out, code
				}
				out[attribute].(map[string][]string)[family.String()] = prefixes

			case "reachable":
				if _, exists := out[attribute]; !exists {
					out[attribute] = map[string]map[string][]string{}
				}
				if value, ok := out[attribute].(map[string]map[string][]string); ok {
					if _, exists := value[family.String()]; exists {
						return out, 1
					}
				}
				nhlength := int(in[offset+header+3])
				nexthop, code := DecodeNexthop(in[offset+header+4:offset+header+4+nhlength], family)
				if code != 0 {
					return out, code
				}
				prefixes, code := DecodePrefixes(in[offset+header+4+nhlength+1:offset+header+length], family, p.LocalMultipath(family, Receive) && p.PeerMultipath(family, Send))
				if code != 0 {
					return out, code
				}
				out[attribute].(map[string]map[string][]string)[family.String()] = map[string][]string{nexthop: prefixes}
			}
		}

		if _, exists := out[attribute]; !exists {
			switch attribute {
			case "origin":
				if length != 1 {
					return out, 5
				}
				if optional || !transitive {
					return out, 4
				}
				switch in[offset+header] {
				case 0:
					out[attribute] = "igp"

				case 1:
					out[attribute] = "egp"

				case 2:
					out[attribute] = "incomplete"

				default:
					return out, 6
				}

			case "as-path":
				if optional || !transitive {
					return out, 4
				}
				path := ""
				if length != 0 {
					count := int(in[offset+header+1])
					width := (length - 2) / count
					if width != 2 && width != 4 {
						return out, 11
					}
					for index := 0; index < count; index++ {
						if width == 2 {
							path += " " + strconv.Itoa(int(binary.BigEndian.Uint16(in[offset+header+2+(index*width):])))

						} else {
							path += " " + strconv.Itoa(int(binary.BigEndian.Uint32(in[offset+header+2+(index*width):])))
						}
					}
				}
				out[attribute] = strings.TrimSpace(path)

			case "as4-path":
				if !optional || !transitive {
					return out, 4
				}
				path := ""
				if length != 0 {
					count := int(in[offset+header+1])
					if (length-2)/count != 4 {
						return out, 9
					}
					for index := 0; index < count; index++ {
						path += " " + strconv.Itoa(int(binary.BigEndian.Uint32(in[offset+header+2+(index*4):])))
					}
				}
				out[attribute] = strings.TrimSpace(path)

			case "next-hop":
				if length != 4 {
					return out, 5
				}
				if optional || !transitive {
					return out, 4
				}
				address, ok := netip.AddrFromSlice(in[offset+header : offset+header+length])
				if !ok {
					return out, 8
				}
				out[attribute] = address.String()

			case "med":
				if length != 4 {
					return out, 5
				}
				if !optional || transitive {
					return out, 4
				}
				out[attribute] = int(binary.BigEndian.Uint32(in[offset+header:]))

			case "local-preference":
				if length != 4 {
					return out, 5
				}
				if optional || !transitive {
					return out, 4
				}
				out[attribute] = int(binary.BigEndian.Uint32(in[offset+header:]))

			case "community":
				if length%4 != 0 {
					return out, 5
				}
				if !optional || !transitive {
					return out, 4
				}
				community := ""
				for index := 0; index < length/4; index++ {
					value := int(binary.BigEndian.Uint32(in[offset+header+(index*4):]))
					community += " " + strconv.Itoa(value>>16) + ":" + strconv.Itoa(value&0xffff)
				}
				out[attribute] = strings.TrimSpace(community)

			// TODO case "extended-community":
			// TODO case "large-community":
			// TODO case "attributes-set":

			default:
				value := ""
				if optional {
					value += " optional"
				}
				if transitive {
					value += " transitive"
				}
				if partial {
					value += " partial"
				}
				out[attribute] = map[string]any{
					"flags": strings.TrimSpace(value),
					"value": "x" + ustr.Hex(in[offset+header:offset+header+length], ' '),
				}
			}
		}

		offset += header + length
	}
	return
}

func (p *Peer) dispatch(event string, payload map[string]any) {
	p.mu.RLock()
	if !p.removed {
		msg := &message{event, p.group, p.speaker, p, payload}
		select {
		case p.messages <- msg:
			select {
			case p.group.messages <- msg:
				select {
				case messages <- msg:

				default:
				}

			default:
			}

		default:
		}
	}
	p.mu.RUnlock()
}

func (p *Peer) to(state string) {
	p.mu.Lock()
	from := p.state
	p.state = state
	p.mu.Unlock()
	if state == stateEstablished && from != stateEstablished {
		p.established = time.Now()
		if _, ok := p.LocalCapability("graceful-restart"); ok && p.eor {
			p.EOR()
		}
	}
	p.dispatch("state", map[string]any{"from": from, "to": state, "reason": p.reason})
	if state == stateIdle {
		p.reason = map[string]any{}
	}
}

func (p *Peer) idle(remove ...bool) {
	p.mu.Lock()
	if p.removed {
		p.mu.Unlock()
		return
	}
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.mu.Unlock()
	p.last, p.sent, p.received = time.Now(), time.Time{}, time.Time{}
	p.peerCapabilities, p.peerFamilies, p.peerMultipath = map[int]Capability{}, map[Family]struct{}{}, map[Family]int{}
	p.peerHold, p.peerASN4 = 0, 0
	p.to(stateIdle)
	if p.template != nil || (len(remove) != 0 && remove[0]) {
		p.mu.Lock()
		if !p.removed {
			close(p.messages)
			p.group.mu.Lock()
			delete(p.group.peers, p.key)
			p.group.mu.Unlock()
			p.speaker.mu.Lock()
			delete(p.speaker.peers, p.key)
			p.speaker.mu.Unlock()
			p.template.mu.Lock()
			delete(p.template.peers, p.key)
			p.template.mu.Unlock()
			p.removed, p.state, p.localASN, p.peerASN = true, stateUnconfigured, 0, 0
		}
		p.mu.Unlock()
	}
}

func (p *Peer) send(message int, data []byte) bool {
	p.mu.RLock()
	_, em := p.PeerCapability("extended-message")
	if p.conn == nil || message < messageOpen || message > messageRefresh || (em && len(data) >= (64<<10)-19) || (!em && len(data) > (4<<10)-19) {
		p.mu.RUnlock()
		return false
	}
	p.dmu.Lock()
	copy(p.data, marker)
	length := 19 + len(data)
	binary.BigEndian.PutUint16(p.data[16:], uint16(length))
	p.data[18] = byte(message)
	copy(p.data[19:], data)
	p.conn.SetWriteDeadline(time.Now().Add(p.hold))
	_, err := p.conn.Write(p.data[:19+len(data)])
	p.dmu.Unlock()
	p.mu.RUnlock()

	p.sent = time.Now()
	if atomic.LoadInt32(&raw) > 0 {
		payload := emptySlice
		if length > 19 {
			payload = make([]byte, length-19)
			copy(payload, data[:length-19])
		}
		p.dispatch("message", map[string]any{"direction": "outbound", "message": messageNames[message], "payload": payload})
	}

	if err != nil {
		p.reason = map[string]any{"code": 0, "subcode": 0, "reason": "peer disconnected abruptly (write error)"}
		p.idle()
		return false
	}

	return true
}

func (p *Peer) open() {
	data, offset, local := make([]byte, (1<<8)+10), 10, p.localASN
	if local >= (64 << 10) {
		local = 23456
	}

	data[0] = 4
	binary.BigEndian.PutUint16(data[1:], uint16(local))
	binary.BigEndian.PutUint16(data[3:], uint16(p.hold/time.Second))
	binary.BigEndian.PutUint32(data[5:], uint32(p.id))
	for family := range p.families {
		if offset <= len(data)-8 {
			binary.BigEndian.PutUint32(data[offset:], 0x02060104)
			binary.BigEndian.PutUint16(data[offset+4:], uint16(family[0]))
			binary.BigEndian.PutUint16(data[offset+6:], uint16(family[1]))
			offset += 8
		}
	}
	if offset <= len(data)-4 { // extended-message
		binary.BigEndian.PutUint32(data[offset:], 0x02020600)
		offset += 4
	}
	if offset <= len(data)-8 { // asn4
		binary.BigEndian.PutUint32(data[offset:], 0x02064104)
		binary.BigEndian.PutUint32(data[offset+4:], uint32(p.localASN))
		offset += 8
	}
	for _, capability := range p.capabilities {
		if offset <= len(data)-(2+2+len(capability.Value)) {
			data[offset], data[offset+1] = 2, byte(2+len(capability.Value))
			data[offset+2], data[offset+3] = byte(capability.Code), byte(len(capability.Value))
			copy(data[offset+4:], capability.Value)
			offset += 2 + 2 + len(capability.Value)
		}
	}
	data[9] = byte(offset - 10)

	p.send(messageOpen, data[:offset])
}

func (p *Peer) notification(code, subcode int, extra ...string) {
	length, message := 2, ""
	if len(extra) > 0 {
		message = extra[0][:min(256, len(extra[0]))]
		length += len(message)
	}
	data := make([]byte, length)
	data[0], data[1] = byte(code), byte(subcode)
	if length > 2 {
		copy(data[2:], message)
	}
	p.send(messageNotification, data)
	p.reason = map[string]any{"code": code, "subcode": subcode, "reason": message}
}

func (p *Peer) keepalive() {
	p.send(messageKeepalive, nil)
}

func (p *Peer) receive(conn net.Conn) {
	p.open()
	p.to(stateOpenSent)
	data := make([]byte, 64<<10)
bailout:
	for {
		hold := p.hold
		if p.peerHold != 0 {
			hold = min(p.hold, p.peerHold)
		}
		if p.State() == stateEstablished {
			conn.SetReadDeadline(time.Now().Add(hold / 3))

		} else {
			conn.SetReadDeadline(time.Now().Add(p.connect))
		}
		_, err := io.ReadAtLeast(conn, data[:19], 19)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				if p.State() == stateEstablished {
					if p.peerHold != 0 && time.Since(p.sent) >= p.peerHold/3 {
						p.keepalive()
					}
					if time.Since(p.received) >= hold {
						p.notification(notificationExpired, 0)
						break bailout
					}
					continue
				}
			}
			p.reason = map[string]any{"code": 1, "subcode": 2, "reason": err.Error()}
			break bailout
		}
		if p.peerHold != 0 && time.Since(p.sent) >= p.peerHold/3 {
			p.keepalive()
		}

		if !bytes.Equal(data[:16], marker) {
			p.notification(notificationHeader, 1, "invalid marker x"+ustr.Hex(data[:16], ' '))
			break bailout
		}
		length, message := int(binary.BigEndian.Uint16(data[16:])), int(data[18])
		if length < 19 {
			p.notification(notificationHeader, 2, "invalid length "+strconv.Itoa(length))
			break bailout
		}
		if message < messageOpen || message > messageRefresh {
			p.notification(notificationHeader, 3, "invalid type "+strconv.Itoa(message))
			break bailout
		}
		if length > 19 {
			if _, err := io.ReadAtLeast(conn, data[:length-19], length-19); err != nil {
				p.reason = map[string]any{"code": notificationHeader, "subcode": 2, "reason": "read " + err.Error()}
				break bailout
			}
		}
		if atomic.LoadInt32(&raw) > 0 {
			payload := emptySlice
			if length > 19 {
				payload = make([]byte, length-19)
				copy(payload, data[:length-19])
			}
			p.dispatch("message", map[string]any{"direction": "inbound", "message": messageNames[message], "payload": payload})
		}

		if message == messageNotification {
			if length >= 19+2 {
				p.reason = map[string]any{"code": int(data[0]), "subcode": int(data[1]), "reason": string(data[2 : length-19])}
			}
			break bailout
		}

		state := p.State()
		if state == stateOpenSent {
			if message == messageOpen {
				if length < 19+10 {
					p.notification(notificationHeader, 2, "invalid length "+strconv.Itoa(length))
					break bailout
				}
				if data[0] != 4 {
					p.notification(notificationOpen, 1, "unsupported version "+strconv.Itoa(int(data[0])))
					break bailout
				}
				hold := int(binary.BigEndian.Uint16(data[3:]))
				if hold > 0 && hold < 3 {
					p.notification(notificationOpen, 6, "unacceptable holdtime "+strconv.Itoa(hold))
					break bailout
				}
				if hold != 0 {
					p.peerHold = time.Duration(hold) * time.Second
					p.peerHold = min(p.hold, p.peerHold)
				}
				if data[5] == 0 && data[6] == 0 && data[7] == 0 && data[8] == 0 {
					p.notification(notificationOpen, 3, "bad identifier")
					break bailout
				}
				if int(data[9])+19+10 != length {
					p.notification(notificationOpen, 4, "invalid optional parameters length "+strconv.Itoa(int(data[9])))
					break bailout
				}

				opts := data[10 : length-19]
				for offset := 0; offset <= len(opts)-4; {
					if opts[offset] != 2 || offset+int(opts[offset+1])+2 > len(opts) {
						p.notification(notificationOpen, 4, "invalid optional parameter x"+ustr.Hex(opts[offset:], ' '))
						break bailout
					}
					caps := opts[offset+2 : offset+int(opts[offset+1])+2]
					for index := 0; index <= len(caps)-2; {
						if index+int(caps[index+1])+2 > len(caps) {
							p.notification(notificationOpen, 4, "invalid optional parameter x"+ustr.Hex(caps[index:], ' '))
							break bailout
						}
						add := true
						if int(caps[index]) == capabilities["multi-protocol"] && caps[index+1] == 4 {
							family := Family{int(binary.BigEndian.Uint16(caps[index+2:])), int(binary.BigEndian.Uint16(caps[index+4:]))}
							if !family.Valid() {
								p.notification(notificationOpen, 7, "invalid family "+family.String())
								break bailout
							}
							p.peerFamilies[family] = struct{}{}
							add = false

						} else if int(caps[index]) == capabilities["asn4"] && caps[index+1] == 4 {
							if p.peerASN4 = int(binary.BigEndian.Uint32(caps[index+2:])); p.peerASN4 == 0 {
								p.notification(notificationOpen, 4, "invalid asn4")
								break bailout
							}
						}
						if add {
							value := emptySlice
							if caps[index+1] != 0 {
								value = make([]byte, caps[index+1])
								copy(value, caps[index+2:])
							}
							capability := Capability{Code: int(caps[index]), Value: value}
							p.peerCapabilities[capability.Code] = capability
						}
						index += 2 + int(caps[index+1])
					}
					offset += 2 + int(opts[offset+1])
				}

				asn := int(binary.BigEndian.Uint16(data[1:]))
				if p.peerASN4 != 0 {
					if p.peerASN4 >= (64 << 10) {
						if asn != 23456 {
							p.notification(notificationOpen, 2, "invalid peer asn-trans "+strconv.Itoa(asn))
							break bailout
						}
						if p.peerASN4 != p.peerASN {
							p.notification(notificationOpen, 2, "invalid peer asn "+strconv.Itoa(p.peerASN4)+" vs "+strconv.Itoa(p.peerASN))
							break bailout
						}

					} else if p.peerASN4 != asn || p.peerASN4 != p.peerASN {
						p.notification(notificationOpen, 2, "invalid peer asn "+strconv.Itoa(p.peerASN4)+" vs "+strconv.Itoa(p.peerASN))
						break bailout
					}

				} else if asn != p.peerASN {
					p.notification(notificationOpen, 2, "invalid peer asn "+strconv.Itoa(asn)+" vs "+strconv.Itoa(p.peerASN))
					break bailout
				}

				p.keepalive()
				p.to(stateOpenConfirm)
				continue
			}
			p.notification(notificationFSM, 1, messageNames[message]+"message in "+state+" state")
			break bailout
		}
		if state == stateOpenConfirm {
			if message == messageKeepalive {
				p.to(stateEstablished)
				p.received = time.Now()
				continue
			}
			p.notification(notificationFSM, 1, messageNames[message]+"message in "+state+" state")
			break bailout
		}
		if state == stateEstablished && message == messageOpen {
			p.notification(notificationFSM, 3, messageNames[message]+"message in "+state+" state")
			break bailout
		}

		p.received = time.Now()
		if message == messageUpdate {
			update := data[:length-19]
			if len(update) < 4 {
				p.notification(notificationHeader, 2, "truncated message")
				break bailout
			}
			ulength := int(binary.BigEndian.Uint16(update))
			if ulength+2 > len(update)-2 {
				p.notification(notificationHeader, 2, "truncated message")
				break bailout
			}
			alength := int(binary.BigEndian.Uint16(update[ulength+2:]))
			if ulength+2+alength+2 > len(update) {
				p.notification(notificationHeader, 2, "truncated message")
				break bailout
			}

			unreachable, attributes, reachable := emptySliceMap, emptyMap, emptySliceMapMap
			if ulength != 0 {
				prefixes, code := DecodePrefixes(update[2:2+ulength], ipv4Unicast, p.LocalMultipath(ipv4Unicast, Receive) && p.PeerMultipath(ipv4Unicast, Send))
				if code != 0 {
					p.notification(notificationUpdate, code)
					break bailout
				}
				unreachable = map[string][]string{ipv4Unicast.String(): prefixes}
			}
			if rlength := len(update) - ulength - 2 - alength - 2; rlength != 0 {
				prefixes, code := DecodePrefixes(update[len(update)-rlength:], ipv4Unicast, p.LocalMultipath(ipv4Unicast, Receive) && p.PeerMultipath(ipv4Unicast, Send))
				if code != 0 {
					p.notification(notificationUpdate, code)
					break bailout
				}
				reachable = map[string]map[string][]string{ipv4Unicast.String(): map[string][]string{"<nexthop>": prefixes}}
			}
			if alength > 0 {
				decoded, code := p.decodeAttributes(update[2+ulength+2 : 2+ulength+2+alength])
				if code > 0 {
					p.notification(notificationUpdate, code)
					break bailout
				}
				if value, exists := decoded["unreachable"].(map[string][]string); exists {
					unreachable = value
					delete(decoded, "unreachable")
				}
				if value, exists := decoded["reachable"].(map[string]map[string][]string); exists {
					reachable = value
					delete(decoded, "reachable")
				}
				if p.localASN == p.peerASN {
					decoded["as-path"] = ""

				} else {
					delete(decoded, "local-preference")
				}
				if len(reachable) != 0 {
					_, exists1 := decoded["origin"]
					_, exists2 := decoded["as-path"]
					_, exists3 := decoded["local-preference"]
					nexthop, ok := j.String(decoded["next-hop"]), true
					for key, value := range reachable {
						if key == ipv4Unicast.String() {
							for subkey, subvalue := range value {
								if subkey == "<nexthop>" {
									if nexthop != "" {
										delete(reachable[key], subkey)
										reachable[key][nexthop] = subvalue

									} else {
										ok = false
									}
								}
							}
						}
					}
					if code < 0 || !exists1 || !exists2 || (p.localASN == p.peerASN && !exists3) || !ok {
						attributes = emptyMap
						if len(unreachable) == 0 {
							unreachable = map[string][]string{}
						}
						for family, prefixes := range reachable {
							for _, prefixes := range prefixes {
								unreachable[family] = append(unreachable[family], prefixes...)
							}
						}
						reachable = emptySliceMapMap

					} else {
						delete(decoded, "next-hop")
						attributes = decoded
					}
				}
			}
			if len(unreachable) == 0 && len(reachable) == 0 { // ipv4 EOR
				unreachable = map[string][]string{ipv4Unicast.String(): []string{}}
			}
			for value := range unreachable {
				if _, exists := p.families[NewFamily(value)]; !exists {
					delete(unreachable, value)
				}
			}
			for value := range reachable {
				if _, exists := p.families[NewFamily(value)]; !exists {
					delete(reachable, value)
				}
			}
			if len(unreachable) != 0 || len(reachable) != 0 {
				p.dispatch("update", map[string]any{"payload": map[string]any{"unreachable": unreachable, "attributes": attributes, "reachable": reachable}})
			}
		}

		if message == messageRefresh {
			_, rr := p.LocalCapability("route-refresh")
			_, err := p.LocalCapability("enhanced-route-refresh")
			if length != 19+4 {
				if err {
					p.notification(notificationRefresh, 1, "x"+ustr.Hex(data, ' '))

				} else {
					p.notification(notificationHeader, 7, "invalid message length "+strconv.Itoa(length))
				}
				break bailout
			}
			code := int(data[2])
			if code == 0 && !rr {
				p.notification(notificationHeader, 3, "unsupported route-refresh")
				break bailout
			}
			if (code == 1 || code == 2) && !err {
				p.notification(notificationHeader, 3, "unsupported enhanced-route-refresh")
				break bailout
			}
			if code == 0 || code == 1 || code == 2 {
				family := Family{int(binary.BigEndian.Uint16(data)), int(data[3])}
				if family.Valid() {
					if _, exists := p.families[family]; exists {
						p.dispatch("refresh", map[string]any{"family": family, "enhanced": code})
					}
				}
			}
		}
	}
	p.idle()
}

func (p *Peer) init() {
	go dispatch("peer", &p.mu, p.messages, p.processors)
	go func() {
		for {
			p.mu.Lock()
			if p.removed {
				p.mu.Unlock()
				break
			}

			if p.enabled && p.state == stateIdle {
				go func() {
					if p.template != nil {
						p.to(stateConnect)
						go p.receive(p.conn)
						return

					} else {
						if pace := time.Since(p.last); pace < p.pace {
							p.to(stateActive)
							time.Sleep(p.pace - pace)
						}
						p.last = time.Now()
						p.to(stateConnect)
						dialer := &net.Dialer{Timeout: p.connect, LocalAddr: p.speaker.local}
						if conn, err := dialer.Dial("tcp", p.remote.String()); err == nil {
							p.mu.Lock()
							p.conn = conn
							p.mu.Unlock()
							go p.receive(conn)
							return
						}
					}
					p.idle()
				}()
			}

			if !p.enabled && p.state != stateIdle {
				go p.notification(notificationCease, 2)
			}

			p.mu.Unlock()
			time.Sleep(time.Second)
		}
	}()
}
