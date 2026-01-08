package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"rho-aias/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type Xdp struct {
	InterfaceName string
	objects       *xdpObjects
	link          *link.Link
	reader        *perf.Reader
	done          chan struct{}
	linkType      string
}

func NewXdp(interface_name string) *Xdp {
	return &Xdp{
		InterfaceName: interface_name,
	}
}

func (x *Xdp) Start() error {
	iface, err := net.InterfaceByName(x.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %s", x.InterfaceName, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("failed to remove memlock: %s", err.Error())
	}
	var ebpfObj xdpObjects
	if err := loadXdpObjects(&ebpfObj, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %s", err.Error())
	}
	x.objects = &ebpfObj
	x.reader, err = perf.NewReader(x.objects.Events, os.Getpagesize())
	if err != nil {
		x.Close()
		return fmt.Errorf("failed to create perf event reader: %s", err.Error())
	}
	x.done = make(chan struct{})

	// ---------- attach XDP ----------
	count := 0
	flagNames := []string{"offload", "driver", "generic"}
	for i, mode := range []link.XDPAttachFlags{link.XDPOffloadMode, link.XDPDriverMode, link.XDPGenericMode} {
		flagName := flagNames[i]
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   x.objects.XdpProg,
			Interface: iface.Index,
			Flags:     mode,
		})
		if err == nil {
			x.linkType = flagName
			x.link = &l
			log.Printf("XDP program attached successfully, current mode: %s", flagName)
			break
		}
		count++
		fmt.Printf("failed to attach XDP program with %s mode: %s\n", flagName, err.Error())
	}
	if count == 3 {
		x.Close()
		return errors.New("failed to attach XDP program")
	}
	return nil
}

func (x *Xdp) Close() {
	log.Println("Xdp close.")
	if x.done != nil {
		close(x.done)
	}
	if x.reader != nil {
		x.reader.Close()
	}
	if x.link != nil {
		(*x.link).Close()
	}
	if x.objects != nil {
		x.objects.Close()
	}
}

func (x *Xdp) GetLinkType() string {
	return x.linkType
}

func (x *Xdp) MonitorEvents() {
	log.Println("MonitorEvents")
	for {
		select {
		case <-x.done:
			log.Println("MonitorEvents exit...")
			return
		default:
			record, err := x.reader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					log.Printf("perf event reader closed, trying to restart eBPF")
					x.Close()
					if err := x.Start(); err != nil {
						log.Fatalf("failed to restart eBPF: %s", err.Error())
					} else {
						log.Printf("eBPF restarted successfully")
					}
					return
				}
				continue
			}
			var pi PacketInfo
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pi); err != nil {
				log.Println(err.Error())
				continue
			}
			log.Println(pi.SrcIP, pi.MatchType)
		}
	}
}

// updateMap 更新内核 map - 支持来源掩码
// iptype: IP 类型
// value: 键值（字节数组）
// blockValue: BlockValue 结构体
// add: true=添加/更新, false=删除
func (x *Xdp) updateMap(iptype utils.IPType, value []byte, blockValue BlockValue, add bool) (err error) {
	switch iptype {
	case utils.IPTypeIPv4:
		if add {
			err = x.objects.Ipv4List.Put(value, blockValue)
		} else {
			err = x.objects.Ipv4List.Delete(value)
		}
	case utils.IPTypeIPV4CIDR:
		if add {
			err = x.objects.Ipv4CidrTrie.Put(value, blockValue)
		} else {
			err = x.objects.Ipv4CidrTrie.Delete(value)
		}
	case utils.IPTypeIPv6:
		if add {
			err = x.objects.Ipv6List.Put(value, blockValue)
		} else {
			err = x.objects.Ipv6List.Delete(value)
		}
	case utils.IPTypeIPv6CIDR:
		if add {
			err = x.objects.Ipv6CidrTrie.Put(value, blockValue)
		} else {
			err = x.objects.Ipv6CidrTrie.Delete(value)
		}
	default:
		return fmt.Errorf("unsupported match type: %v", iptype)
	}
	return err
}

// AddRule 添加手动规则（设置 MANUAL 位）
func (x *Xdp) AddRule(value string) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	log.Println(bytes, iptype)
	// 手动规则设置 MANUAL 位 (0x04)
	blockValue := NewBlockValue(SourceMaskManual)
	return x.updateMap(iptype, bytes, blockValue, true)
}

// DeleteRule 删除规则（完全删除，不论来源）
func (x *Xdp) DeleteRule(value string) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	// 传入空的 BlockValue 用于删除（实际不会使用）
	return x.updateMap(iptype, bytes, BlockValue{}, false)
}

// AddRuleWithSource 添加指定来源的规则
func (x *Xdp) AddRuleWithSource(value string, sourceMask uint32) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	blockValue := NewBlockValue(sourceMask)
	return x.updateMap(iptype, bytes, blockValue, true)
}

func (x *Xdp) GetRule() ([]Rule, error) {
	var res []Rule
	ipv4List, err := x.ipv4List()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4List...)
	ipv4TrieKeyList, err := x.ipv4TrieKey()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4TrieKeyList...)
	return res, nil
}

// ipv4List 获取 IPv4 精确匹配规则列表
func (x *Xdp) ipv4List() ([]Rule, error) {
	iter := x.objects.Ipv4List.Iterate()
	var key []byte
	var value BlockValue
	var res []Rule
	for iter.Next(&key, &value) {
		ip := net.IP(key)
		res = append(res, Rule{
			Key:     ip.String(),
			Value:   value,
			Sources: MaskToSourceIDs(value.SourceMask),
		})
	}
	if err := iter.Err(); err != nil {
		return []Rule{}, err
	}
	return res, nil
}

// ipv4TrieKey 获取 IPv4 CIDR 规则列表
func (x *Xdp) ipv4TrieKey() ([]Rule, error) {
	iter := x.objects.Ipv4CidrTrie.Iterate()
	var key IPv4TrieKey
	var value BlockValue
	var res []Rule
	for iter.Next(&key, &value) {
		ip := net.IP(key.Addr[:])
		res = append(res, Rule{
			Key:     fmt.Sprintf("%s/%d", ip.String(), key.PrefixLen),
			Value:   value,
			Sources: MaskToSourceIDs(value.SourceMask),
		})
	}
	if err := iter.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// BatchAddRules 批量添加规则（高性能）
// sourceMask: 来源掩码，指定规则的来源
func (x *Xdp) BatchAddRules(values []string, sourceMask uint32) error {
	// 按类型分组并准备批量数据
	ipv4ExactKeys := make([][4]byte, 0)
	ipv4ExactValues := make([]BlockValue, 0)
	ipv4CIDRKeys := make([]IPv4TrieKey, 0)
	ipv4CIDRValues := make([]BlockValue, 0)

	// 预创建 BlockValue 模板
	blockValue := NewBlockValue(sourceMask)

	for _, value := range values {
		bytes, iptype, err := utils.ParseValueToBytes(value)
		if err != nil {
			log.Printf("Failed to parse value %s: %v", value, err)
			continue
		}

		switch iptype {
		case utils.IPTypeIPv4:
			var key [4]byte
			copy(key[:], bytes)
			ipv4ExactKeys = append(ipv4ExactKeys, key)
			ipv4ExactValues = append(ipv4ExactValues, blockValue)
		case utils.IPTypeIPV4CIDR:
			// bytes 格式: [4 bytes prefixlen (LE) + 4 bytes IP]
			var key IPv4TrieKey
			copy(key.Addr[:], bytes[4:])
			key.PrefixLen = binary.LittleEndian.Uint32(bytes[:4])
			ipv4CIDRKeys = append(ipv4CIDRKeys, key)
			ipv4CIDRValues = append(ipv4CIDRValues, blockValue)
		default:
			log.Printf("Unsupported IP type: %v for value %s", iptype, value)
		}
	}

	// 批量更新 IPv4 精确匹配
	if len(ipv4ExactKeys) > 0 {
		if err := x.batchUpdateMap(x.objects.Ipv4List, ipv4ExactKeys, ipv4ExactValues); err != nil {
			return fmt.Errorf("batch update IPv4 exact match failed: %w", err)
		}
	}

	// 批量更新 IPv4 CIDR
	if len(ipv4CIDRKeys) > 0 {
		if err := x.batchUpdateMap(x.objects.Ipv4CidrTrie, ipv4CIDRKeys, ipv4CIDRValues); err != nil {
			return fmt.Errorf("batch update IPv4 CIDR failed: %w", err)
		}
	}

	return nil
}

// batchUpdateMap 通用批量更新方法
func (x *Xdp) batchUpdateMap(m interface{}, keys, values interface{}) error {
	// 使用迭代器方式批量更新
	// 由于 cilium/ebpf 的 BatchUpdate API 比较复杂，这里使用循环方式
	// 虽然不是真正的批量，但比每次单独创建请求要高效

	// 使用 *ebpf.Map 的通用 Put(key, value interface{}) 方法
	emap, ok := m.(*ebpf.Map)
	if !ok {
		return fmt.Errorf("map type assertion failed: expected *ebpf.Map")
	}

	switch v := keys.(type) {
	case [][4]byte:
		vals := values.([]BlockValue)
		for i, key := range v {
			if err := emap.Put(key, vals[i]); err != nil {
				return fmt.Errorf("put key %v failed: %w", key, err)
			}
		}
	case []IPv4TrieKey:
		vals := values.([]BlockValue)
		for i, key := range v {
			if err := emap.Put(key, vals[i]); err != nil {
				return fmt.Errorf("put key %v failed: %w", key, err)
			}
		}
	}

	return nil
}

// BatchDeleteRules 批量删除规则
func (x *Xdp) BatchDeleteRules(values []string) error {
	var errs []error
	for _, value := range values {
		if err := x.DeleteRule(value); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("batch delete failed with %d errors, first: %v", len(errs), errs[0])
	}
	return nil
}
