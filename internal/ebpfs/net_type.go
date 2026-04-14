package ebpfs

type MatchType uint32

const (
	NoMatch         MatchType = 0
	MatchByIP4Exact MatchType = 1
	MatchByIP4CIDR  MatchType = 2
	MatchByGeoBlock MatchType = 6 // 地域封禁匹配
	MatchByWhitelist MatchType = 7 // IP 白名单匹配（直接放行）
)

type PacketInfo struct {
	SrcIP      [4]byte
	DstIP      [4]byte
	EthProto   uint16
	IPProtocol uint8      // IP 协议类型 (TCP=6, UDP=17, ICMP=1)
	TCPFlags   uint8      // TCP 标志位 (SYN=0x02, ACK=0x10, etc.)
	DstPort    uint16     // 目标端口 (TCP/UDP, 网络字节序)
	PktSize    uint32
	MatchType  MatchType
}


