package ebpfs

import (
	"fmt"
)

type MatchType uint32

const (
	NoMatch         MatchType = 0
	MatchByIP4Exact MatchType = 1
	MatchByIP4CIDR  MatchType = 2
	MatchByIP6Exact MatchType = 3
	MatchByIP6CIDR  MatchType = 4
	MatchByMAC      MatchType = 5
)

type MatchRule struct {
	MatchType MatchType
	Value     string
}

type EthernetType uint16

func (et EthernetType) String() string {
	return fmt.Sprintf("%d", et)
}

type IPProtocol uint16

func (protocol IPProtocol) String() string {
	return fmt.Sprintf("%d", protocol)
}

type PacketInfo struct {
	SrcIP     [4]byte
	DstIP     [4]byte
	SrcIPv6   [16]byte
	DstIPv6   [16]byte
	SrcPort   uint16
	DstPort   uint16
	SrcMAC    [6]byte
	DstMAC    [6]byte
	EthProto  EthernetType
	IPProto   IPProtocol
	PktSize   uint32
	MatchType MatchType
}

type Packet struct {
	Timestamp int64
	SrcMAC    string
	SrcIP     string
	DstMAC    string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Size      uint32
	Country   string
	City      string
	EthType   EthernetType
	IPProto   IPProtocol
	MatchType MatchType
}
