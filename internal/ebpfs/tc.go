package ebpfs

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

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

// AddRule adds a TC filtering rule
func (t *Tc) AddRule(srcIP string, dstPort uint16, proto string) error {
	protoNum := ProtoToIPProto(proto)
	if protoNum == 0 {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", proto)
	}

	// Convert IP to bytes and check for wildcard
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return fmt.Errorf("invalid source IP: %s", srcIP)
	}

	// Get the 32-bit representation (network byte order)
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", srcIP)
	}

	// Convert to host byte order for the key
	srcIPHost := binary.BigEndian.Uint32(ip4)

	// Create the key
	key := TcRuleKey{
		SrcIP:   srcIPHost,
		DstPort: dstPort,
		Proto:   protoNum,
		Padding: 0,
	}

	// Insert into map (value = 1 means rule is active)
	if err := t.objects.TcRules.Put(&key, uint8(1)); err != nil {
		return fmt.Errorf("failed to add TC rule: %w", err)
	}

	log.Printf("TC rule added: src_ip=%s, dst_port=%d, proto=%s", srcIP, dstPort, proto)
	return nil
}

// DeleteRule removes a TC filtering rule
func (t *Tc) DeleteRule(srcIP string, dstPort uint16, proto string) error {
	protoNum := ProtoToIPProto(proto)
	if protoNum == 0 {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", proto)
	}

	// Convert IP to bytes and check for wildcard
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return fmt.Errorf("invalid source IP: %s", srcIP)
	}

	// Get the 32-bit representation (network byte order)
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", srcIP)
	}

	// Convert to host byte order for the key
	srcIPHost := binary.BigEndian.Uint32(ip4)

	// Create the key
	key := TcRuleKey{
		SrcIP:   srcIPHost,
		DstPort: dstPort,
		Proto:   protoNum,
		Padding: 0,
	}

	// Delete from map
	if err := t.objects.TcRules.Delete(&key); err != nil {
		// Key not found is still considered an error for deletion
		return fmt.Errorf("failed to delete TC rule (may not exist): %w", err)
	}

	log.Printf("TC rule deleted: src_ip=%s, dst_port=%d, proto=%s", srcIP, dstPort, proto)
	return nil
}

// GetRules returns all TC filtering rules
func (t *Tc) GetRules() ([]TcRule, error) {
	var rules []TcRule

	iter := t.objects.TcRules.Iterate()
	var key TcRuleKey
	var value uint8

	for iter.Next(&key, &value) {
		// Convert host byte order back to IP string
		srcIPBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(srcIPBytes, key.SrcIP)
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

	return rules, nil
}
