package ebpfs

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"rho-aias/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Tc represents a TC eBPF program manager
type Tc struct {
	InterfaceName string
	objects       *tcObjects
	link          *link.Link
}

// NewTc creates a new TC manager for the given interface
func NewTc(interfaceName string) *Tc {
	return &Tc{
		InterfaceName: interfaceName,
	}
}

// Start loads and attaches the TC program to the interface
func (t *Tc) Start() error {
	iface, err := net.InterfaceByName(t.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", t.InterfaceName, err)
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("failed to remove memlock: %s", err.Error())
	}

	// Load eBPF objects
	var tcObj tcObjects
	if err := loadTcObjects(&tcObj, nil); err != nil {
		return fmt.Errorf("failed to load TC eBPF objects: %w", err)
	}
	t.objects = &tcObj

	// Attach TC program to ingress
	// Try TCX API first (kernel 6.6+), fall back to traditional netlink
	attachedLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   t.objects.TcProg,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		// TCX not available, try traditional netlink attachment
		log.Printf("TCX not available, falling back to netlink attachment")
		t.Close()
		return fmt.Errorf("TC attachment failed (both TCX and netlink): %w", err)
	}

	t.link = &attachedLink
	log.Printf("TC program attached to interface %s (ingress)", t.InterfaceName)

	return nil
}

// Close detaches the TC program and cleans up resources
func (t *Tc) Close() {
	log.Println("Tc close.")
	if t.link != nil {
		(*t.link).Close()
	}
	if t.objects != nil {
		t.objects.Close()
	}
}

// AddRule adds a TC filtering rule (supports exact IP and CIDR)
func (t *Tc) AddRule(srcIP string, dstPort uint16, proto string) error {
	protoNum := ProtoToIPProto(proto)
	if protoNum == 0 {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", proto)
	}

	// Parse IP/CIDR using utils.ParseValueToBytes
	bytes, iptype, err := utils.ParseValueToBytes(srcIP)
	if err != nil {
		return fmt.Errorf("invalid source IP: %w", err)
	}

	switch iptype {
	case utils.IPTypeIPv4:
		// Exact IPv4 match -> tc_rules HASH map
		srcIPHost := binary.BigEndian.Uint32(bytes)
		key := tcTcRuleKey{
			SrcIp:   srcIPHost,
			DstPort: dstPort,
			Proto:   protoNum,
			Padding: 0,
		}
		if err := t.objects.TcRules.Put(&key, uint8(1)); err != nil {
			return fmt.Errorf("failed to add TC rule: %w", err)
		}
		log.Printf("TC rule added: src_ip=%s, dst_port=%d, proto=%s (exact IPv4)", srcIP, dstPort, proto)

	case utils.IPTypeIPV4CIDR:
		// IPv4 CIDR match -> tc_ipv4_cidr LPM_TRIE map
		// bytes format: [4 bytes prefixlen (LE) + 4 bytes IP]
		var key tcIpv4TrieKey
		key.Prefixlen = binary.LittleEndian.Uint32(bytes[:4])
		// bytes[4:8] is network byte order, key.Addr is also network byte order (uint32)
		key.Addr = binary.BigEndian.Uint32(bytes[4:8])

		value := tcTcCidrValue{
			DstPort: dstPort,
			Proto:   protoNum,
		}
		if err := t.objects.TcIpv4Cidr.Put(&key, &value); err != nil {
			return fmt.Errorf("failed to add TC CIDR rule: %w", err)
		}
		log.Printf("TC rule added: src_ip=%s, dst_port=%d, proto=%s (IPv4 CIDR)", srcIP, dstPort, proto)

	case utils.IPTypeIPv6:
		// IPv6 exact match -> tc_ipv6_rules HASH map
		var key tcTcIpv6RuleKey
		copy(key.SrcIp.In6U.U6Addr8[:], bytes)
		key.DstPort = dstPort
		key.Proto = protoNum

		if err := t.objects.TcIpv6Rules.Put(&key, uint8(1)); err != nil {
			return fmt.Errorf("failed to add TC rule: %w", err)
		}
		log.Printf("TC rule added: src_ip=%s, dst_port=%d, proto=%s (exact IPv6)", srcIP, dstPort, proto)

	case utils.IPTypeIPv6CIDR:
		// IPv6 CIDR match -> tc_ipv6_cidr LPM_TRIE map
		// bytes format: [4 bytes prefixlen (LE) + 16 bytes IP]
		var key tcIpv6TrieKey
		key.Prefixlen = binary.LittleEndian.Uint32(bytes[:4])
		copy(key.Addr.In6U.U6Addr8[:], bytes[4:20])

		value := tcTcCidrValue{
			DstPort: dstPort,
			Proto:   protoNum,
		}
		if err := t.objects.TcIpv6Cidr.Put(&key, &value); err != nil {
			return fmt.Errorf("failed to add TC CIDR rule: %w", err)
		}
		log.Printf("TC rule added: src_ip=%s, dst_port=%d, proto=%s (IPv6 CIDR)", srcIP, dstPort, proto)

	default:
		return fmt.Errorf("unsupported IP type for TC rule: %s", srcIP)
	}

	return nil
}

// DeleteRule removes a TC filtering rule (supports exact IP and CIDR)
func (t *Tc) DeleteRule(srcIP string, dstPort uint16, proto string) error {
	protoNum := ProtoToIPProto(proto)
	if protoNum == 0 {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", proto)
	}

	// Parse IP/CIDR using utils.ParseValueToBytes
	bytes, iptype, err := utils.ParseValueToBytes(srcIP)
	if err != nil {
		return fmt.Errorf("invalid source IP: %w", err)
	}

	switch iptype {
	case utils.IPTypeIPv4:
		// Exact IPv4 match -> tc_rules HASH map
		srcIPHost := binary.BigEndian.Uint32(bytes)
		key := tcTcRuleKey{
			SrcIp:   srcIPHost,
			DstPort: dstPort,
			Proto:   protoNum,
			Padding: 0,
		}
		if err := t.objects.TcRules.Delete(&key); err != nil {
			return fmt.Errorf("failed to delete TC rule (may not exist): %w", err)
		}
		log.Printf("TC rule deleted: src_ip=%s, dst_port=%d, proto=%s (exact IPv4)", srcIP, dstPort, proto)

	case utils.IPTypeIPV4CIDR:
		// IPv4 CIDR match -> tc_ipv4_cidr LPM_TRIE map
		var key tcIpv4TrieKey
		key.Prefixlen = binary.LittleEndian.Uint32(bytes[:4])
		key.Addr = binary.BigEndian.Uint32(bytes[4:8])

		if err := t.objects.TcIpv4Cidr.Delete(&key); err != nil {
			return fmt.Errorf("failed to delete TC CIDR rule (may not exist): %w", err)
		}
		log.Printf("TC rule deleted: src_ip=%s, dst_port=%d, proto=%s (IPv4 CIDR)", srcIP, dstPort, proto)

	case utils.IPTypeIPv6:
		// IPv6 exact match -> tc_ipv6_rules HASH map
		var key tcTcIpv6RuleKey
		copy(key.SrcIp.In6U.U6Addr8[:], bytes)
		key.DstPort = dstPort
		key.Proto = protoNum

		if err := t.objects.TcIpv6Rules.Delete(&key); err != nil {
			return fmt.Errorf("failed to delete TC rule (may not exist): %w", err)
		}
		log.Printf("TC rule deleted: src_ip=%s, dst_port=%d, proto=%s (exact IPv6)", srcIP, dstPort, proto)

	case utils.IPTypeIPv6CIDR:
		// IPv6 CIDR match -> tc_ipv6_cidr LPM_TRIE map
		var key tcIpv6TrieKey
		key.Prefixlen = binary.LittleEndian.Uint32(bytes[:4])
		copy(key.Addr.In6U.U6Addr8[:], bytes[4:20])

		if err := t.objects.TcIpv6Cidr.Delete(&key); err != nil {
			return fmt.Errorf("failed to delete TC CIDR rule (may not exist): %w", err)
		}
		log.Printf("TC rule deleted: src_ip=%s, dst_port=%d, proto=%s (IPv6 CIDR)", srcIP, dstPort, proto)

	default:
		return fmt.Errorf("unsupported IP type for TC rule: %s", srcIP)
	}

	return nil
}

// GetRules returns all TC filtering rules (from both exact and CIDR maps)
func (t *Tc) GetRules() ([]TcRule, error) {
	var rules []TcRule

	// Iterate exact IPv4 rules (HASH map)
	{
		iter := t.objects.TcRules.Iterate()
		var key tcTcRuleKey
		var value uint8

		for iter.Next(&key, &value) {
			// Convert host byte order back to IP string
			srcIPBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(srcIPBytes, key.SrcIp)
			srcIP := net.IP(srcIPBytes).String()

			rule := TcRule{
				SrcIP:   srcIP,
				DstPort: key.DstPort,
				Proto:   IPProtoToProto(key.Proto),
			}
			rules = append(rules, rule)
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to iterate TC rules: %w", err)
		}
	}

	// Iterate IPv4 CIDR rules (LPM_TRIE map)
	{
		iter := t.objects.TcIpv4Cidr.Iterate()
		var key tcIpv4TrieKey
		var value tcTcCidrValue

		for iter.Next(&key, &value) {
			// Convert CIDR key back to CIDR string
			prefixLen := key.Prefixlen
			addrBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(addrBytes, key.Addr)
			srcIP := net.IP(addrBytes).String()
			cidr := fmt.Sprintf("%s/%d", srcIP, prefixLen)

			rule := TcRule{
				SrcIP:   cidr,
				DstPort: value.DstPort,
				Proto:   IPProtoToProto(value.Proto),
			}
			rules = append(rules, rule)
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to iterate TC IPv4 CIDR rules: %w", err)
		}
	}

	// Iterate exact IPv6 rules (HASH map)
	{
		iter := t.objects.TcIpv6Rules.Iterate()
		var key tcTcIpv6RuleKey
		var value uint8

		for iter.Next(&key, &value) {
			srcIP := net.IP(key.SrcIp.In6U.U6Addr8[:]).String()

			rule := TcRule{
				SrcIP:   srcIP,
				DstPort: key.DstPort,
				Proto:   IPProtoToProto(key.Proto),
			}
			rules = append(rules, rule)
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to iterate TC IPv6 rules: %w", err)
		}
	}

	// Iterate IPv6 CIDR rules (LPM_TRIE map)
	{
		iter := t.objects.TcIpv6Cidr.Iterate()
		var key tcIpv6TrieKey
		var value tcTcCidrValue

		for iter.Next(&key, &value) {
			// Convert CIDR key back to CIDR string
			prefixLen := key.Prefixlen
			srcIP := net.IP(key.Addr.In6U.U6Addr8[:]).String()
			cidr := fmt.Sprintf("%s/%d", srcIP, prefixLen)

			rule := TcRule{
				SrcIP:   cidr,
				DstPort: value.DstPort,
				Proto:   IPProtoToProto(value.Proto),
			}
			rules = append(rules, rule)
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to iterate TC IPv6 CIDR rules: %w", err)
		}
	}

	return rules, nil
}
