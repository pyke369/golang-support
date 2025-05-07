package netlink

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

// netlink communication
var sequence uint32

func init() {
	sequence = uint32(time.Now().Unix())
}

type attr struct {
	header   *syscall.NlAttr
	data     []byte
	size     int
	children []*attr
}
type request struct {
	header    *syscall.NlMsghdr
	data      []byte
	attrs     []*attr
	offset    int
	marshaled []byte
}

func newAttr(cmd int, data []byte, attrs []*attr) *attr {
	if cmd == syscall.IFLA_UNSPEC {
		return &attr{
			header: &syscall.NlAttr{},
			data:   data,
			size:   len(data),
		}
	}
	length := syscall.SizeofNlAttr + len(data)
	for _, attr := range attrs {
		if attr != nil {
			length += attr.size
		}
	}
	return &attr{
		header: &syscall.NlAttr{
			Len:  uint16(length),
			Type: uint16(cmd),
		},
		data:     data,
		children: attrs,
		size:     (length + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1),
	}
}
func newRequest(cmd, flags int, data []byte, attrs []*attr) *request {
	length := syscall.NLMSG_HDRLEN + len(data)
	for _, attr := range attrs {
		length += attr.size
	}
	return &request{
		header: &syscall.NlMsghdr{
			Len:   uint32(length),
			Type:  uint16(cmd),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | uint16(flags),
			Seq:   atomic.AddUint32(&sequence, 1),
		},
		data:  data,
		attrs: attrs,
	}
}
func (nr *request) marshalAttrs(attrs []*attr, level int) {
	for _, attr := range attrs {
		if attr != nil {
			if attr.header.Type == syscall.IFLA_UNSPEC {
				copy(nr.marshaled[nr.offset:], attr.data)
				nr.offset += attr.size
			} else {
				binary.LittleEndian.PutUint16(nr.marshaled[nr.offset:], attr.header.Len)
				binary.LittleEndian.PutUint16(nr.marshaled[nr.offset+2:], attr.header.Type)
				if len(attr.data) != 0 {
					copy(nr.marshaled[nr.offset+4:], attr.data)
					nr.offset += attr.size
				} else {
					nr.offset += 4
					nr.marshalAttrs(attr.children, level+1)
				}
			}
		}
	}
}
func (nr *request) marshal() []byte {
	nr.marshaled = make([]byte, nr.header.Len)
	binary.LittleEndian.PutUint32(nr.marshaled[0:], nr.header.Len)
	binary.LittleEndian.PutUint16(nr.marshaled[4:], nr.header.Type)
	binary.LittleEndian.PutUint16(nr.marshaled[6:], nr.header.Flags)
	binary.LittleEndian.PutUint32(nr.marshaled[8:], nr.header.Seq)
	binary.LittleEndian.PutUint32(nr.marshaled[12:], nr.header.Pid)
	copy(nr.marshaled[16:], nr.data)
	nr.offset = 16 + len(nr.data)
	nr.marshalAttrs(nr.attrs, 0)
	return nr.marshaled
}
func exec(request *request, trace ...bool) (err error) {
	handle, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	address := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(handle, address); err != nil {
		return err
	}
	defer syscall.Close(handle)
	out := request.marshal()
	if len(trace) > 0 && trace[0] {
		os.Stderr.WriteString("-- REQ --\n")
		os.Stderr.WriteString(hex.Dump(out))
	}
	if err := syscall.Sendto(handle, out, 0, address); err != nil {
		return err
	}
	in := make([]byte, syscall.Getpagesize())
	for {
		n, _, err := syscall.Recvfrom(handle, in, 0)
		if err != nil {
			return err
		}
		if n < syscall.NLMSG_HDRLEN {
			return syscall.EINVAL
		}
		if len(trace) > 0 && trace[0] {
			os.Stderr.WriteString("-- ACK --\n")
			os.Stderr.WriteString(hex.Dump(in[:n]))
		}
		msgs, err := syscall.ParseNetlinkMessage(in[:n])
		if err != nil {
			return err
		}
		for _, msg := range msgs {
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				return err

			case syscall.NLMSG_ERROR:
				if msg.Header.Len >= 4 {
					if errno := -int32(binary.LittleEndian.Uint32(msg.Data)); errno != 0 {
						return syscall.Errno(errno)
					}
				}
			}
		}
	}
}

// interfaces
func Interfaces(filter ...string) (itfs []map[string]any) {
	itfs = []map[string]any{}
	if value, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC); err == nil {
		if msgs, err := syscall.ParseNetlinkMessage(value); err == nil {
		outer1:
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.NLMSG_DONE:
					break outer1

				case syscall.RTM_NEWLINK:
					imsg, flags := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0])), []string{}
					for key, value := range map[int]string{
						syscall.IFF_UP:          "UP",
						syscall.IFF_BROADCAST:   "BROADCAST",
						syscall.IFF_LOOPBACK:    "LOOPBACK",
						syscall.IFF_POINTOPOINT: "POINT-TO-POINT",
						syscall.IFF_RUNNING:     "RUNNING",
						syscall.IFF_NOARP:       "NOARP",
						syscall.IFF_MASTER:      "MASTER",
						syscall.IFF_SLAVE:       "SLAVE",
						syscall.IFF_MULTICAST:   "MULTICAST",
						1 << 16:                 "LOWER_UP",
						1 << 17:                 "DORMANT",
						1 << 18:                 "ECHO",
					} {
						if int(imsg.Flags)&key != 0 {
							flags = append(flags, value)
						}
					}
					itf := map[string]any{"index": imsg.Index}
					switch imsg.Type {
					case syscall.ARPHRD_LOOPBACK:
						itf["type"] = "loopback"

					case syscall.ARPHRD_ETHER, syscall.ARPHRD_EETHER:
						itf["type"] = "ethernet"

					case syscall.ARPHRD_IEEE80211, syscall.ARPHRD_IEEE80211_PRISM, syscall.ARPHRD_IEEE80211_RADIOTAP:
						itf["type"] = "wifi"

					case syscall.ARPHRD_TUNNEL, syscall.ARPHRD_TUNNEL6:
						itf["type"] = "tunnel"

					case syscall.ARPHRD_NONE, syscall.ARPHRD_VOID:
						itf["type"] = "none"

					default:
						itf["type"] = "other"
					}
					if attrs, err := syscall.ParseNetlinkRouteAttr(&msg); err == nil {
						for _, attr := range attrs {
							switch attr.Attr.Type & 0x00ff {
							case syscall.IFLA_ADDRESS:
								if hwaddr := ustr.Hex(attr.Value, ':'); hwaddr != "00:00:00:00:00:00" {
									itf["hwaddr"] = hwaddr
								}

							case syscall.IFLA_IFNAME:
								itf["name"] = string(attr.Value[:len(attr.Value)-1])

							case syscall.IFLA_MTU:
								itf["mtu"] = int(binary.LittleEndian.Uint32(attr.Value))

							case syscall.IFLA_LINK:
								itf["link"] = int(binary.LittleEndian.Uint16(attr.Value))

							case syscall.IFLA_MASTER:
								itf["master"] = int(binary.LittleEndian.Uint16(attr.Value))

							case syscall.IFLA_TXQLEN:
								itf["qlen"] = int(binary.LittleEndian.Uint32(attr.Value))

							case syscall.IFLA_OPERSTATE:
								if state := int(attr.Value[0]); state >= 1 && state <= 6 {
									itf["state"] = []string{"", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"}[state]
								}

							case 0x21: // IFLA_CARRIER
								if attr.Value[0] == 0 {
									flags = append(flags, "NO-CARRIER")
								}
							}
						}
					}
					sort.Strings(flags)
					itf["flags"] = flags
					itfs = append(itfs, itf)
				}
			}
		}
	}
	for _, itf1 := range itfs {
		if link := j.Number(itf1["link"]); link != 0 {
			for _, itf2 := range itfs {
				if j.Number(itf2["index"]) == link {
					itf1["link"] = j.String(itf2["name"])
					break
				}
			}
		}
		if link := j.Number(itf1["link"]); link != 0 {
			itf1["link"] = "if" + strconv.Itoa(int(link))
		}
		if master := j.Number(itf1["master"]); master != 0 {
			for _, itf2 := range itfs {
				if j.Number(itf2["index"]) == master {
					itf1["master"] = j.String(itf2["name"])
					break
				}
			}
		}
		if master := j.Number(itf1["master"]); master != 0 {
			itf1["master"] = "if" + strconv.Itoa(int(master))
		}
	}
	slaves := map[string][]string{}
	for _, itf := range itfs {
		if master := j.String(itf["master"]); master != "" {
			slaves[master] = append(slaves[master], j.String(itf["name"]))
		}
	}
	for master, list := range slaves {
		sort.Strings(list)
		for _, itf := range itfs {
			if j.String(itf["name"]) == master {
				itf["slaves"] = list
				break
			}
		}
	}
	if value, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC); err == nil {
		if msgs, err := syscall.ParseNetlinkMessage(value); err == nil {
		outer2:
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.NLMSG_DONE:
					break outer2

				case syscall.RTM_NEWADDR:
					amsg := (*syscall.IfAddrmsg)(unsafe.Pointer(&msg.Data[0]))
					for _, itf := range itfs {
						if int(j.Number(itf["index"])) == int(amsg.Index) {
							if attrs, err := syscall.ParseNetlinkRouteAttr(&msg); err == nil {
								for _, attr := range attrs {
									if attr.Attr.Type == syscall.IFA_ADDRESS {
										switch amsg.Family {
										case syscall.AF_INET:
											address := net.IPv4(attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3])
											itf["addrs"] = append(j.StringSlice(itf["addrs"]), address.String()+"/"+strconv.Itoa(int(amsg.Prefixlen)))

										case syscall.AF_INET6:
											address := make(net.IP, net.IPv6len)
											copy(address, attr.Value)
											itf["addrs"] = append(j.StringSlice(itf["addrs"]), address.String()+"/"+strconv.Itoa(int(amsg.Prefixlen)))
										}
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if len(filter) != 0 {
		expression, itfs2 := strings.TrimSpace(filter[0]), []map[string]any{}
		if strings.HasPrefix(expression, "~") {
			expression = strings.TrimSpace(expression[1:])
		} else {
			expression = "^" + expression + "$"
		}
		matcher := rcache.Get(expression)
		for _, itf := range itfs {
			if matcher.MatchString(j.String(itf["name"])) {
				itfs2 = append(itfs2, itf)
			}
		}
		itfs = itfs2
	}
	return
}

func getOption(name string, options ...map[string]any) any {
	if len(options) != 0 && options[0] != nil {
		return options[0][name]
	}
	return nil
}

func AddDummy(name string, options ...map[string]any) error {
	// TODO support dummy interfaces
	return nil
}
func AddVlan(name string, vlan int, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg, value1, value2 := [syscall.SizeofIfInfomsg]byte{}, [4]byte{}, [2]byte{}
			binary.LittleEndian.PutUint32(value1[:], uint32(index))
			binary.LittleEndian.PutUint16(value2[:], uint16(vlan))
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_LINK, value1[:], nil),
					newAttr(syscall.IFLA_IFNAME, []byte(name+"."+strconv.Itoa(vlan)+"\000"), nil),
					newAttr(syscall.IFLA_LINKINFO, nil, []*attr{
						newAttr(1 /*IFLA_INFO_KIND*/, []byte("vlan"), nil),
						newAttr(2 /*IFLA_INFO_DATA*/, nil, []*attr{
							newAttr(1 /*IFLA_VLAN_ID*/, value2[:], nil),
						}),
					}),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func AddVirtualPair(name1, name2 string, options ...map[string]any) error {
	imsg := [syscall.SizeofIfInfomsg]byte{}
	return exec(newRequest(
		syscall.RTM_NEWLINK,
		syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
		imsg[:],
		[]*attr{
			newAttr(syscall.IFLA_IFNAME, []byte(name1+"\000"), nil),
			newAttr(syscall.IFLA_LINKINFO, nil, []*attr{
				newAttr(1 /*IFLA_INFO_KIND*/, []byte("veth"), nil),
				newAttr(2 /*IFLA_INFO_DATA*/, nil, []*attr{
					newAttr(1 /*VETH_INFO_PEER*/, nil, []*attr{
						newAttr(syscall.IFLA_UNSPEC, imsg[:], nil),
						newAttr(syscall.IFLA_IFNAME, []byte(name2+"\000"), nil),
					}),
				}),
			}),
		}), j.Boolean(getOption("trace", options...)))
}
func AddBridge(name string, options ...map[string]any) error {
	imsg, value := [syscall.SizeofIfInfomsg]byte{}, [4]byte{}
	binary.LittleEndian.PutUint32(value[:], 1)
	return exec(newRequest(
		syscall.RTM_NEWLINK,
		syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
		imsg[:],
		[]*attr{
			newAttr(syscall.IFLA_IFNAME, []byte(name+"\000"), nil),
			newAttr(syscall.IFLA_LINKINFO, nil, []*attr{
				newAttr(1 /*IFLA_INFO_KIND*/, []byte("bridge"), nil),
				nil,
				// newAttr(2 /*IFLA_INFO_DATA*/, nil, []*attr{ // TODO
				// 	newAttr(5 /*IFLA_BR_STP_STATE*/, value[:], nil),
				//  TODO 1 /*IFLA_BR_FORWARD_DELAY*/ = 2 secs (instead of default 15 secs)
				// }),
			}),
		}), j.Boolean(getOption("trace", options...)))
}
func AddBond(name string, options ...map[string]any) error {
	imsg := [syscall.SizeofIfInfomsg]byte{}
	return exec(newRequest(
		syscall.RTM_NEWLINK,
		syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
		imsg[:],
		[]*attr{
			newAttr(syscall.IFLA_IFNAME, []byte(name+"\000"), nil),
			newAttr(syscall.IFLA_LINKINFO, nil, []*attr{
				newAttr(1 /*IFLA_INFO_KIND*/, []byte("bond"), nil),
				// newAttr(2 /*IFLA_INFO_DATA*/, nil, []*attr{
				// 	newAttr(x /*IFLA_BOND_MODE*/, value[:], nil),
				// }),
				// TODO mode option
			}),
		}), j.Boolean(getOption("trace", options...)))
}
func RenameInterface(from, to string, options ...map[string]any) error {
	if itfs := Interfaces(from); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg := [syscall.SizeofIfInfomsg]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_IFNAME, []byte(to+"\000"), nil),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func SetInterfaceNamespace(name string, pid int, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg, value := [syscall.SizeofIfInfomsg]byte{}, [4]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			binary.LittleEndian.PutUint32(value[:], uint32(pid))
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_NET_NS_PID, value[:], nil),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func LinkInterface(master, slave string, options ...map[string]any) error {
	if master == slave {
		return syscall.Errno(syscall.EINVAL)
	}
	imaster, islave, imsg, value := 0, 0, [syscall.SizeofIfInfomsg]byte{}, [4]byte{}
	for _, itf := range Interfaces("~^(" + master + "|" + slave + ")$") {
		if j.String(itf["name"]) == master {
			imaster = int(j.Number(itf["index"]))
		}
		if j.String(itf["name"]) == slave {
			islave = int(j.Number(itf["index"]))
		}
	}
	if islave != 0 && (master == "" || imaster != 0) {
		binary.LittleEndian.PutUint32(imsg[4:], uint32(islave))
		binary.LittleEndian.PutUint32(value[:], uint32(imaster))
		return exec(newRequest(
			syscall.RTM_NEWLINK,
			0,
			imsg[:],
			[]*attr{
				newAttr(syscall.IFLA_MASTER, value[:], nil),
			}), j.Boolean(getOption("trace", options...)))
	}
	return syscall.Errno(syscall.ENODEV)
}
func UnlinkInterface(slave string, options ...map[string]any) error {
	return LinkInterface("", slave, options...)
}
func RemoveInterface(name string, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg := [syscall.SizeofIfInfomsg]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			return exec(newRequest(
				syscall.RTM_DELLINK,
				0,
				imsg[:],
				nil), j.Boolean(getOption("trace", options...)))
		}
	}
	return nil
}
func SetInterfaceState(name string, up bool, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg := [syscall.SizeofIfInfomsg]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			if up {
				binary.LittleEndian.PutUint32(imsg[8:], syscall.IFF_UP)
			}
			binary.LittleEndian.PutUint32(imsg[12:], syscall.IFF_UP)
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				nil), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func SetInterfaceHWAddress(name, address string, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg, value := [syscall.SizeofIfInfomsg]byte{}, [6]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			if _, err := fmt.Sscanf(address, "%02x:%02x:%02x:%02x:%02x:%02x", &value[0], &value[1], &value[2], &value[3], &value[4], &value[5]); err != nil { // TODO fmt usage
				return syscall.Errno(syscall.EINVAL)
			}
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_ADDRESS, value[:], nil),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func SetInterfaceMTU(name string, mtu int, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg, value := [syscall.SizeofIfInfomsg]byte{}, [4]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			binary.LittleEndian.PutUint32(value[:], uint32(mtu))
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_MTU, value[:], nil),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func SetInterfaceQueue(name string, qlen int, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			imsg, value := [syscall.SizeofIfInfomsg]byte{}, [4]byte{}
			binary.LittleEndian.PutUint32(imsg[4:], index)
			binary.LittleEndian.PutUint32(value[:], uint32(qlen))
			return exec(newRequest(
				syscall.RTM_NEWLINK,
				0,
				imsg[:],
				[]*attr{
					newAttr(syscall.IFLA_TXQLEN, value[:], nil),
				}), j.Boolean(getOption("trace", options...)))
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func AddInterfaceAddress(name, address string, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			if address, network, err := net.ParseCIDR(address); err == nil {
				ones, bits := network.Mask.Size()
				amsg := [syscall.SizeofIfAddrmsg]byte{syscall.AF_INET, byte(ones), syscall.IFA_F_NODAD}
				if bits == 128 {
					amsg[0] = syscall.AF_INET6
				} else {
					address = address.To4()
				}
				binary.LittleEndian.PutUint32(amsg[4:], index)
				return exec(newRequest(
					syscall.RTM_NEWADDR,
					syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
					amsg[:],
					[]*attr{
						newAttr(syscall.IFA_LOCAL, address[:], nil),
						newAttr(syscall.IFA_ADDRESS, address[:], nil),
					}), j.Boolean(getOption("trace", options...)))
			}
			return syscall.Errno(syscall.EINVAL)
		}
	}
	return syscall.Errno(syscall.ENODEV)
}
func RemoveInterfaceAddress(name, address string, options ...map[string]any) error {
	if itfs := Interfaces(name); len(itfs) == 1 {
		if index := uint32(j.Number(itfs[0]["index"])); index != 0 {
			if address, network, err := net.ParseCIDR(address); err == nil {
				ones, bits := network.Mask.Size()
				amsg := [syscall.SizeofIfAddrmsg]byte{syscall.AF_INET, byte(ones), syscall.IFA_F_NODAD}
				if bits == 128 {
					amsg[0] = syscall.AF_INET6
				} else {
					address = address.To4()
				}
				binary.LittleEndian.PutUint32(amsg[4:], index)
				return exec(newRequest(
					syscall.RTM_DELADDR,
					0,
					amsg[:],
					[]*attr{
						newAttr(syscall.IFA_LOCAL, address[:], nil),
						newAttr(syscall.IFA_ADDRESS, address[:], nil),
					}), j.Boolean(getOption("trace", options...)))
			}
			return syscall.Errno(syscall.EINVAL)
		}
	}
	return syscall.Errno(syscall.ENODEV)
}

// routes
func Routes(filter ...string) (routes []map[string]any) {
	routes = []map[string]any{}
	if value, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC); err == nil {
		if msgs, err := syscall.ParseNetlinkMessage(value); err == nil {
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.NLMSG_DONE:
					return

				case syscall.RTM_NEWROUTE:
					rmsg := (*syscall.RtMsg)(unsafe.Pointer(&msg.Data[0]))
					fmt.Printf("family:%d Dst_len:%d Src_len:%d Table:%d\n", rmsg.Family, rmsg.Dst_len, rmsg.Src_len, rmsg.Table)
					if attrs, err := syscall.ParseNetlinkRouteAttr(&msg); err == nil {
						for _, attr := range attrs {
							fmt.Printf("- ATTR-%04x %v\n", attr.Attr.Type, attr.Value)
						}
					}
				}
			}
		}
	}
	return
}
func AddRoute() error {
	// TODO support adding routes
	return nil
}
func RemoveRoute() error {
	// TODO support removing routes
	return nil
}
