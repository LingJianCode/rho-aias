package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"rho-aias/utils"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// BlockLogCallback 阻断日志回调函数类型
type BlockLogCallback func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32)

type Xdp struct {
	InterfaceName string
	objects       *xdpObjects
	link          *link.Link
	reader        *perf.Reader
	done          chan struct{}
	linkType      string
	callback      BlockLogCallback // 阻断事件回调
}

func NewXdp(interface_name string) *Xdp {
	return &Xdp{
		InterfaceName: interface_name,
	}
}

// SetCallback 设置阻断事件回调函数
func (x *Xdp) SetCallback(callback BlockLogCallback) {
	x.callback = callback
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
		// 检查 done 通道（非阻塞）
		select {
		case <-x.done:
			log.Println("MonitorEvents exit...")
			return
		default:
		}

		// 阻塞式读取 perf 事件
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
			// 其他错误，检查 done 后继续
			select {
			case <-x.done:
				log.Println("MonitorEvents exit after error...")
				return
			default:
				continue
			}
		}

		var pi PacketInfo
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pi); err != nil {
			log.Printf("Failed to parse packet info: %v", err)
			continue
		}

		// 解析 IP 地址
		srcIP := formatIP(pi.SrcIP, pi.SrcIPv6, uint16(pi.EthProto))
		dstIP := formatIP(pi.DstIP, pi.DstIPv6, uint16(pi.EthProto))
		matchTypeStr := matchTypeToString(pi.MatchType)

		log.Printf("Blocked packet - Src: %s, MatchType: %s", srcIP, matchTypeStr)

		// 触发回调
		if x.callback != nil {
			// 根据 matchType 确定规则来源
			ruleSource := getRuleSourceFromMatchType(pi.MatchType)
			countryCode := "" // geo_block 时需要额外处理
			x.callback(srcIP, dstIP, matchTypeStr, ruleSource, countryCode, pi.PktSize)
		}
	}
}

// formatIP 格式化 IP 地址
func formatIP(ipv4 [4]byte, ipv6 [16]byte, ethProto uint16) string {
	if ethProto == 0x0800 { // ETH_P_IP
		addr := netip.AddrFrom4(ipv4)
		return addr.String()
	} else if ethProto == 0x86DD { // ETH_P_IPV6
		addr := netip.AddrFrom16(ipv6)
		return addr.String()
	}
	return ""
}

// matchTypeToString 将匹配类型转换为字符串
func matchTypeToString(mt MatchType) string {
	switch mt {
	case MatchByIP4Exact:
		return "ip4_exact"
	case MatchByIP4CIDR:
		return "ip4_cidr"
	case MatchByIP6Exact:
		return "ip6_exact"
	case MatchByIP6CIDR:
		return "ip6_cidr"
	case MatchByMAC:
		return "mac"
	case MatchByGeoBlock:
		return "geo_block"
	default:
		return "unknown"
	}
}

// getRuleSourceFromMatchType 根据匹配类型获取规则来源
// 注意：这只是默认值，实际来源应该从 eBPF map 中查询
func getRuleSourceFromMatchType(mt MatchType) string {
	// 默认返回 unknown，实际应用中需要查询 eBPF map 获取精确来源
	return "unknown"
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
			err = x.objects.BlockIpv4List.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv4List.Delete(value)
		}
	case utils.IPTypeIPV4CIDR:
		if add {
			err = x.objects.BlockIpv4CidrTrie.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv4CidrTrie.Delete(value)
		}
	case utils.IPTypeIPv6:
		if add {
			err = x.objects.BlockIpv6List.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv6List.Delete(value)
		}
	case utils.IPTypeIPv6CIDR:
		if add {
			err = x.objects.BlockIpv6CidrTrie.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv6CidrTrie.Delete(value)
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
	iter := x.objects.BlockIpv4List.Iterate()
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
	iter := x.objects.BlockIpv4CidrTrie.Iterate()
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
		for i, key := range ipv4ExactKeys {
			if err := x.objects.BlockIpv4List.Put(key, ipv4ExactValues[i]); err != nil {
				return fmt.Errorf("put IPv4 exact key %v failed: %w", key, err)
			}
		}
	}

	// 批量更新 IPv4 CIDR
	if len(ipv4CIDRKeys) > 0 {
		for i, key := range ipv4CIDRKeys {
			if err := x.objects.BlockIpv4CidrTrie.Put(key, ipv4CIDRValues[i]); err != nil {
				return fmt.Errorf("put IPv4 CIDR key %v failed: %w", key, err)
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

// ============================================
// Geo-Blocking 相关方法
// ============================================

// UpdateGeoConfig 更新地域封禁配置到内核
func (x *Xdp) UpdateGeoConfig(enabled bool, mode uint32) error {
	config := NewGeoConfig(enabled, mode)
	key := uint32(0)
	return x.objects.GeoConfig.Put(&key, &config)
}

// AddGeoIPRule 添加单条 GeoIP 规则
// 格式: "1.0.0.0/24,CN"
func (x *Xdp) AddGeoIPRule(cidrWithCountry string) error {
	// 解析格式: "1.0.0.0/24,CN"
	parts := strings.Split(cidrWithCountry, ",")
	if len(parts) < 2 {
		return fmt.Errorf("invalid format, expected: \"cidr,country_code\"")
	}

	cidr := parts[0]
	countryCode := parts[1]

	// 解析 CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR failed: %w", err)
	}

	// 创建 LPM trie key
	var key IPv4TrieKey
	copy(key.Addr[:], ipNet.IP.To4())
	ones, _ := ipNet.Mask.Size()
	key.PrefixLen = uint32(ones)

	// 将国家代码转换为 uint32 (例如: "CN" -> 0x434e0000)
	var countryValue uint32
	if len(countryCode) >= 2 {
		countryValue = uint32(countryCode[0])<<24 | uint32(countryCode[1])<<16
	}

	return x.objects.GeoIpv4Whitelist.Put(&key, &countryValue)
}

// BatchAddGeoIPRules 批量添加 GeoIP 规则
// 格式: ["1.0.0.0/24,CN", "2.0.0.0/24,US", ...]
func (x *Xdp) BatchAddGeoIPRules(cidrs []string) error {
	keys := make([]IPv4TrieKey, 0, len(cidrs))
	values := make([]uint32, 0, len(cidrs))

	for _, cidrWithCountry := range cidrs {
		// 解析格式: "1.0.0.0/24,CN"
		parts := strings.Split(cidrWithCountry, ",")
		if len(parts) < 2 {
			log.Printf("[GeoBlocking] Invalid format: %s", cidrWithCountry)
			continue
		}

		cidr := parts[0]
		countryCode := parts[1]

		// 解析 CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[GeoBlocking] Failed to parse CIDR %s: %v", cidr, err)
			continue
		}

		// 只处理 IPv4 网络（跳过 IPv6）
		if ipNet.IP.To4() == nil {
			log.Printf("[GeoBlocking] Skipping non-IPv4 network: %s", cidr)
			continue
		}

		// 创建 LPM trie key
		var key IPv4TrieKey
		copy(key.Addr[:], ipNet.IP.To4())
		ones, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(ones)

		// 将国家代码转换为 uint32
		var countryValue uint32
		if len(countryCode) >= 2 {
			countryValue = uint32(countryCode[0])<<24 | uint32(countryCode[1])<<16
		}

		keys = append(keys, key)
		values = append(values, countryValue)
	}

	// 批量更新
	for i := range keys {
		if err := x.objects.GeoIpv4Whitelist.Put(&keys[i], &values[i]); err != nil {
			return fmt.Errorf("put GeoIP rule %d failed: %w", i, err)
		}
	}

	return nil
}

// BatchDeleteGeoIPRules 批量删除 GeoIP 规则
func (x *Xdp) BatchDeleteGeoIPRules(cidrs []string) error {
	var errs []error
	for _, cidrWithCountry := range cidrs {
		// 解析格式: "1.0.0.0/24,CN"
		parts := strings.Split(cidrWithCountry, ",")
		if len(parts) < 1 {
			errs = append(errs, fmt.Errorf("invalid format: %s", cidrWithCountry))
			continue
		}

		cidr := parts[0]

		// 解析 CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse CIDR %s failed: %w", cidr, err))
			continue
		}

		// 创建 LPM trie key
		var key IPv4TrieKey
		copy(key.Addr[:], ipNet.IP.To4())
		ones, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(ones)

		if err := x.objects.GeoIpv4Whitelist.Delete(&key); err != nil {
			errs = append(errs, fmt.Errorf("delete %s failed: %w", cidr, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("batch delete failed with %d errors, first: %v", len(errs), errs[0])
	}
	return nil
}

// GetGeoIPRules 获取所有 GeoIP 规则
func (x *Xdp) GetGeoIPRules() ([]string, error) {
	var rules []string
	iter := x.objects.GeoIpv4Whitelist.Iterate()

	var key IPv4TrieKey
	var countryValue uint32

	for iter.Next(&key, &countryValue) {
		ip := net.IP(key.Addr[:])
		cidr := fmt.Sprintf("%s/%d", ip.String(), key.PrefixLen)

		// 将 uint32 转换回国家代码
		countryCode := ""
		if countryValue != 0 {
			b1 := byte((countryValue >> 24) & 0xFF)
			b2 := byte((countryValue >> 16) & 0xFF)
			countryCode = string([]byte{b1, b2})
		}

		rules = append(rules, fmt.Sprintf("%s,%s", cidr, countryCode))
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate GeoIP rules failed: %w", err)
	}

	return rules, nil
}

// GetGeoConfigEnabled 获取当前 geo_config 的 enabled 状态
func (x *Xdp) GetGeoConfigEnabled() uint32 {
	key := uint32(0)
	config := GeoConfig{}
	if err := x.objects.GeoConfig.Lookup(&key, &config); err != nil {
		return 0 // 查询失败，返回未启用
	}
	return config.Enabled
}
