package ubgp

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/ustr"
)

const (
	stateUnconfigured = "unconfigured"
	stateIdle         = "idle"
	stateActive       = "active"
	stateConnect      = "connect"
	stateOpenSent     = "open-sent"
	stateOpenConfirm  = "open-confirm"
	stateEstablished  = "established"

	messageOpen         = 1
	messageUpdate       = 2
	messageNotification = 3
	messageKeepalive    = 4
	messageRefresh      = 5

	notificationHeader  = 1
	notificationOpen    = 2
	notificationUpdate  = 3
	notificationExpired = 4
	notificationFSM     = 5
	notificationCease   = 6
	notificationRefresh = 7
)

type Capability struct {
	Code  int
	Value []byte
}

type Family [2]int

var (
	marker           = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	emptySlice       = []byte{}
	emptyMap         = map[string]any{}
	emptySliceMap    = map[string][]string{}
	emptySliceMapMap = map[string]map[string][]string{}
	ipv4Unicast      = NewFamily("ipv4 unicast")
	// ipv6Unicast      = NewFamily("ipv6 unicast")
	messageNames = map[int]string{
		1: "open",
		2: "update",
		3: "notification",
		4: "keepalive",
		5: "refresh",
	}
	capabilities = map[string]int{
		"multi-protocol":         1,
		"route-refresh":          2,
		"outbound-filtering":     3,
		"extended-nexthop":       5,
		"extended-message":       6,
		"bgpsec":                 7,
		"multiple-labels":        8,
		"bgp-role":               9,
		"graceful-restart":       64,
		"asn4":                   65,
		"dynamic":                67,
		"multisession":           68,
		"add-path":               69,
		"enhanced-route-refresh": 70,
		"llgr":                   71,
		"routing-policy":         72,
		"fqdn":                   73,
		"bfd":                    74,
		"software-version":       75,
		"paths-limit":            76,
	}
	afis = map[string]int{
		"ipv4":           1,
		"ipv6":           2,
		"nsap":           3,
		"hdlc":           4,
		"bbn":            5,
		"802":            6,
		"e163":           7,
		"e164":           8,
		"f69":            9,
		"x121":           10,
		"ipx":            11,
		"appletalk":      12,
		"decnet":         13,
		"banyan":         14,
		"e164-nsap":      15,
		"dns":            16,
		"dist-name":      17,
		"as-number":      18,
		"xtp-ipv4":       19,
		"xtp-ipv6":       20,
		"xtp-native":     21,
		"fchan-wwpn":     22,
		"fchan-wwnn":     23,
		"gwid":           24,
		"l2vpn":          25,
		"mpls-sei":       26,
		"mpls-lei":       27,
		"mpls-pei":       28,
		"mt-ipv4":        29,
		"mt-ipv6":        30,
		"bgp-sfc":        31,
		"eigrp-common":   16384,
		"eigrp-ipv4":     16385,
		"eigrp-ipv6":     16386,
		"lcaf":           16387,
		"bgp-ls":         16388,
		"mac-48b":        16389,
		"mac-64b":        16390,
		"oui":            16391,
		"mac-f24":        16392,
		"mac-f40":        16393,
		"ipv6-64":        16394,
		"rbridge":        16395,
		"trill":          16396,
		"uuid":           16397,
		"routing-policy": 16398,
		"mpls-ns":        16399,
	}
	safis = map[string]int{
		"unicast":            1,
		"multicast":          2,
		"mpls":               4,
		"mcast-vpn":          5,
		"pseudowire":         6,
		"mcast-vpls":         8,
		"bgp-sfc":            9,
		"tunnel":             64,
		"vpls":               65,
		"bgp-mdt":            66,
		"bgp-4o6":            67,
		"bgp-6o4":            68,
		"l1vpn":              69,
		"evpn":               70,
		"bgp-ls":             71,
		"bgp-ls-vpn":         72,
		"srte":               73,
		"sdwan":              74,
		"routing-policy":     75,
		"classful-transport": 76,
		"flow-tunnel":        77,
		"mcast-tree":         78,
		"bgp-dps":            79,
		"bgp-ls-spf":         80,
		"bgp-car":            83,
		"bgp-car-vpn":        84,
		"bgp-mup":            85,
		"mpls-vpn":           128,
		"mpls-vpn-multicast": 129,
		"rtc":                132,
		"flow":               133,
		"flow-vpn":           134,
		"vpn-ad":             140,
	}
	attributes = map[string]int{
		"origin":                  1,
		"as-path":                 2,
		"next-hop":                3,
		"med":                     4,
		"local-preference":        5,
		"atomic-aggregate":        6,
		"aggregator":              7,
		"community":               8,
		"originator":              9,
		"cluster-list":            10,
		"reachable":               14,
		"unreachable":             15,
		"extended-community":      16,
		"as4-path":                17,
		"as4-aggregator":          18,
		"pmsi-tunnel":             22,
		"tunnel-encapsulation":    23,
		"traffic-engineering":     24,
		"ipv6-extended-community": 25,
		"aigp":                    26,
		"pe-labels":               27,
		"bgp-ls":                  29,
		"large-community":         32,
		"bgpsec-path":             33,
		"otc":                     35,
		"sfp":                     37,
		"bfd":                     38,
		"bgp-sid":                 40,
		"attributes-set":          128,
	}
)

func NewCapability(in string) (capability Capability) {
	parts := strings.Split(strings.TrimRight(strings.ToLower(in), ") "), "(")
	parts[0] = strings.TrimSpace(parts[0])
	code, _ := strconv.Atoi(parts[0])
	if code == 0 {
		code = capabilities[parts[0]]
	}
	if code > 0 && code < 255 {
		capability = Capability{Code: code}
		if len(parts) > 1 {
			if parts[1] = strings.ToLower(strings.TrimSpace(parts[1])); parts[1] == "" {
				return
			}
			if parts[1][0] == 'x' {
				if value, err := hex.DecodeString(strings.ReplaceAll(parts[1][1:], " ", "")); err == nil {
					capability.Value = value
					return
				}
			}
			switch code {
			case capabilities["multi-protocol"]:
				if family := NewFamily(parts[1]); family.Valid() {
					capability.Value = binary.BigEndian.AppendUint16(capability.Value, uint16(family[0]))
					capability.Value = binary.BigEndian.AppendUint16(capability.Value, uint16(family[1]))
				}

			case capabilities["asn4"]:
				if strings.HasPrefix(strings.ToUpper(parts[1]), "AS") {
					parts[1] = parts[1][2:]
				}
				if asn, err := strconv.Atoi(parts[1]); err == nil && asn > 0 && asn < 1<<32 {
					capability.Value = binary.BigEndian.AppendUint32(capability.Value, uint32(asn))
				}

			case capabilities["add-path"]:
				for _, item := range strings.Split(parts[1], ",") {
					if parts := strings.Fields(strings.TrimSpace(item)); len(parts) >= 2 {
						flag := 0
						if strings.Contains(parts[0], "receive") {
							flag |= 0x01
						}
						if strings.Contains(parts[0], "send") {
							flag |= 0x02
						}
						if flag != 0 {
							family := NewFamily(strings.Join(parts[1:], " "))
							if family.Valid() {
								capability.Value = binary.BigEndian.AppendUint16(capability.Value, uint16(family[0]))
								capability.Value = append(capability.Value, []byte{byte(family[1]), byte(flag)}...)
							}
						}
					}
				}
			}
		}
	}
	return
}
func (c Capability) String() (out string) {
	if c.Code > 0 && c.Code < 255 {
		for key, value := range capabilities {
			if value == c.Code {
				out = key
				break
			}
		}
		if out == "" {
			out = strconv.Itoa(c.Code)
		}
		switch c.Code {
		case capabilities["multi-protocol"]:
			if len(c.Value) != 4 {
				return ""
			}
			family := Family{int(binary.BigEndian.Uint16(c.Value)), int(binary.BigEndian.Uint16(c.Value[2:]))}
			if !family.Valid() {
				return ""
			}
			out += "(" + family.String() + ")"

		case capabilities["asn4"]:
			if len(c.Value) != 4 {
				return ""
			}
			out += "" + strconv.Itoa(int(binary.BigEndian.Uint32(c.Value))) + ")"

		case capabilities["add-path"]:
			if len(c.Value)%4 != 0 {
				return ""
			}
			families := map[Family]int{}
			for offset := 0; offset < len(c.Value); offset += 4 {
				if c.Value[offset+3] != 0 {
					family := Family{int(binary.BigEndian.Uint16(c.Value[offset:])), int(c.Value[offset+2])}
					if family.Valid() {
						families[family] = int(c.Value[offset+3])
					}
				}
			}
			if len(families) == 0 {
				return ""
			}
			out += "("
			for family, flag := range families {
				switch flag {
				case 1:
					out += "receive "
				case 2:
					out += "send "
				case 3:
					out += "receive/send "
				}
				out += family.String() + ", "
			}
			out = strings.TrimRight(strings.TrimSpace(out), ",") + ")"

		case capabilities["extended-message"], capabilities["route-refresh"], capabilities["extended-route-refresh"]:
			if len(c.Value) != 0 {
				return ""
			}

		default:
			if len(c.Value) != 0 {
				out += "(x" + ustr.Hex(c.Value, ' ') + ")"
			}
		}
	}
	return
}
func (c Capability) Valid() bool {
	return c.String() != ""
}

func NewFamily(in string) (family Family) {
	if parts := strings.Fields(in); len(parts) == 2 {
		afi, _ := strconv.Atoi(parts[0])
		safi, _ := strconv.Atoi(parts[1])
		if afi == 0 {
			afi = afis[parts[0]]
		}
		if safi == 0 {
			safi = safis[parts[1]]
		}
		if afi > 0 && afi < 65535 && safi > 0 && safi < 255 && safi != 3 && !(safi >= 130 && safi <= 131) && !(safi >= 135 && safi <= 139) && !(safi >= 141 && safi <= 240) {
			family = Family{afi, safi}
		}
	}
	return
}
func (f Family) String() string {
	if f[0] > 0 && f[0] < 65535 && f[1] > 0 && f[1] < 255 && f[1] != 3 && !(f[1] >= 130 && f[1] <= 131) && !(f[1] >= 135 && f[1] <= 139) && !(f[1] >= 141 && f[1] <= 240) {
		afi, safi := "", ""
		for key, value := range afis {
			if value == f[0] {
				afi = key
				break
			}
		}
		if afi == "" {
			afi = strconv.Itoa(f[0])
		}
		for key, value := range safis {
			if value == f[1] {
				safi = key
				break
			}
		}
		if safi == "" {
			safi = strconv.Itoa(f[1])
		}
		return afi + " " + safi
	}
	return ""
}
func (f Family) Valid() bool {
	return f.String() != ""
}

func EncodeNexthop(in string, family Family) (out []byte) {
	if family.Valid() {
		parts := strings.Split(in, "|")
		parts[0] = strings.ToLower(strings.TrimSpace(parts[0]))
		switch family[0] {
		case afis["ipv4"], afis["ipv6"]:
			if addr, err := netip.ParseAddr(parts[0]); err == nil {
				if addr.Is4() {
					out = append(out, 4)
				} else {
					out = append(out, 16)
				}
				out = append(out, addr.AsSlice()...)
				if addr.Is6() && len(parts) > 1 {
					if addr, err := netip.ParseAddr(strings.TrimSpace(parts[1])); err == nil {
						out = append(out, addr.AsSlice()...)
						out[0] += 16
					}
				}
			}

		default:
			if in[0] == 'x' {
				if value, err := hex.DecodeString(strings.ReplaceAll(in[1:], " ", "")); err == nil {
					value = value[:min(255, len(value))]
					out = append(out, byte(len(value)))
					out = append(out, value...)
				}
			}
		}
	}
	return
}
func DecodeNexthop(in []byte, family Family) (out string, code int) {
	code = 10
	switch family[0] {
	case afis["ipv4"], afis["ipv6"]:
		if len(in) != 4 && len(in) != 16 && len(in) != 32 {
			return
		}
		addr, ok := netip.AddrFromSlice(in[:min(16, len(in))])
		if !ok {
			return
		}
		out = addr.String()
		if len(in) == 32 {
			if addr, ok := netip.AddrFromSlice(in[16:]); ok {
				out += "|" + addr.String()
			}
		}

	default:
		if len(in) != 0 {
			out = "x" + ustr.Hex(in, ' ')
		}
	}
	return out, 0
}

func EncodePrefix(in string, family Family, multipath bool) (out []byte) {
	if family.Valid() {
		parts, path := strings.Split(in, "|"), 0
		if len(parts) > 1 {
			path, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		parts[0] = strings.ToLower(strings.TrimSpace(parts[0]))
		switch family[0] {
		case afis["ipv4"], afis["ipv6"]:
			if prefix, err := netip.ParsePrefix(parts[0]); err == nil {
				addr := prefix.Addr().AsSlice()
				if (family[0] == afis["ipv4"] && prefix.Addr().Is4()) || (family[0] == afis["ipv6"] && prefix.Addr().Is6()) {
					if multipath {
						out = binary.BigEndian.AppendUint32(out, uint32(path))
					}
					out = append(out, byte(prefix.Bits()))
					out = append(out, addr[:int((prefix.Bits()+7)/8)]...)
				}
			}

		default:
			if parts[0][0] == 'x' {
				if value, err := hex.DecodeString(strings.ReplaceAll(parts[0][1:], " ", "")); err == nil {
					if multipath {
						out = binary.BigEndian.AppendUint32(out, uint32(path))
					}
					out = append(out, value...)
				}
			}
		}
	}
	return
}
func DecodePrefixes(in []byte, family Family, multipath bool) (out []string, code int) {
	out, code = []string{}, 10
	if !family.Valid() {
		return
	}
	path := 0
	switch family[0] {
	case afis["ipv4"], afis["ipv6"]:
		for offset := 0; offset < len(in); {
			if offset >= len(in) {
				return
			}
			if multipath {
				if offset+4 >= len(in) {
					return
				}
				path = int(binary.BigEndian.Uint32(in[offset:]))
				offset += 4
			}
			bits := int(in[offset])
			length, prefix := int((bits+7)/8), ""
			if offset+length >= len(in) {
				return
			}
			offset++
			switch family[0] {
			case afis["ipv4"]:
				var addr [4]byte

				if length > 4 {
					return
				}
				copy(addr[:], in[offset:offset+length])
				prefix = netip.PrefixFrom(netip.AddrFrom4(addr), bits).String()

			case afis["ipv6"]:
				var addr [16]byte

				if length > 16 {
					return
				}
				copy(addr[:], in[offset:offset+length])
				prefix = netip.PrefixFrom(netip.AddrFrom16(addr), bits).String()

			}
			if multipath {
				prefix += "|" + strconv.Itoa(path)
			}
			out = append(out, prefix)
			offset += length
		}

	default:
		if len(in) > 0 {
			out = append(out, "x"+ustr.Hex(in, ' '))
		}
	}
	return out, 0
}
