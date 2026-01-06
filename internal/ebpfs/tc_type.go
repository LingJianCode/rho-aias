package ebpfs

// TcRule represents a TC filtering rule
type TcRule struct {
	SrcIP   string `json:"src_ip"`   // Source IP address (0.0.0.0 = wildcard)
	DstPort uint16 `json:"dst_port"` // Destination port
	Proto   string `json:"proto"`    // Protocol: "tcp" or "udp"
}

// TcRuleKey is the key used in the eBPF map
type TcRuleKey struct {
	SrcIP   uint32 // Source IP in host byte order (0 = wildcard)
	DstPort uint16 // Destination port in host byte order
	Proto   uint16 // Protocol: IPPROTO_TCP=6, IPPROTO_UDP=17
	Padding uint16 // Padding to 8-byte boundary
}

// Proto constants
const (
	ProtoTCP  = 6 // IPPROTO_TCP
	ProtoUDP  = 17 // IPPROTO_UDP
)

// ProtoToIPProto converts protocol string to IP protocol number
func ProtoToIPProto(proto string) uint16 {
	switch proto {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	default:
		return 0
	}
}

// IPProtoToProto converts IP protocol number to string
func IPProtoToProto(proto uint16) string {
	switch proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return "unknown"
	}
}
