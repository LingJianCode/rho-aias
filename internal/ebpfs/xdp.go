package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"rho-aias/internal/logger"
	"rho-aias/utils"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BlockLogCallback 阻断日志回调函数类型
type BlockLogCallback func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32)

type Xdp struct {
	InterfaceName string
	objects       *xdpObjects
	link          *link.Link
	reader       *ringbuf.Reader
	done          chan struct{}
	doneOnce      sync.Once
	linkType      string
	callback      BlockLogCallback // 阻断事件回调
	closeMu       sync.Mutex       // 保护 Close/Start 的并发安全
	anomalyPorts  []uint32         // 已配置的异常检测端口列表（用于 ARRAY 清理）
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
		logger.Warnf("[XDP] Failed to remove memlock: %s", err.Error())
	}
	var ebpfObj xdpObjects
	if err := loadXdpObjects(&ebpfObj, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %s", err.Error())
	}
	x.objects = &ebpfObj
	x.reader, err = ringbuf.NewReader(x.objects.Events)
	if err != nil {
		x.Close()
		return fmt.Errorf("failed to create ringbuf reader: %s", err.Error())
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
			logger.Infof("[XDP] Program attached successfully, current mode: %s", flagName)
			break
		}
		count++
		logger.Debugf("[XDP] Failed to attach with %s mode: %s", flagName, err.Error())
	}
	if count == 3 {
		x.Close()
		return errors.New("failed to attach XDP program")
	}
	return nil
}

func (x *Xdp) Close() {
	logger.Info("[XDP] Close")
	x.doneOnce.Do(func() {
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
	})
}

// ============================================
// Feature Flags 相关方法 (空 map 快速跳过优化)
// ============================================

const (
	featureWhitelist = 1 << 0 // whitelist maps have entries
	featureBlacklist = 1 << 1 // blacklist maps have entries
)

// updateFeatureFlags 扫描所有白名单/黑名单 map，更新 feature_flags 位图
// 由用户空间在规则增删后调用，使 eBPF 跳过空 map 的无用 lookup
func (x *Xdp) updateFeatureFlags() {
	if x.objects == nil {
		return
	}

	flags := uint32(0)

	// 检查白名单 maps 是否有条目
	if x.mapHasEntries(x.objects.WhitelistIpv4List) ||
		x.mapHasEntries(x.objects.WhitelistIpv4CidrTrie) ||
		x.mapHasEntries(x.objects.WhitelistIpv6List) ||
		x.mapHasEntries(x.objects.WhitelistIpv6CidrTrie) {
		flags |= featureWhitelist
	}

	// 检查黑名单 maps 是否有条目
	if x.mapHasEntries(x.objects.BlockIpv4List) ||
		x.mapHasEntries(x.objects.BlockIpv4CidrTrie) ||
		x.mapHasEntries(x.objects.BlockIpv6List) ||
		x.mapHasEntries(x.objects.BlockIpv6CidrTrie) {
		flags |= featureBlacklist
	}

	key := uint32(0)
	if err := x.objects.FeatureFlags.Put(&key, &flags); err != nil {
		logger.Warnf("[XDP] Failed to update feature flags: %v", err)
	}
}

// mapHasEntries 检查 eBPF map 是否包含任何条目
func (x *Xdp) mapHasEntries(m *ebpf.Map) bool {
	iter := m.Iterate()
	var k, v []byte
	has := iter.Next(&k, &v)
	return has
}

func (x *Xdp) MonitorEvents() {
	logger.Info("[XDP] MonitorEvents started")
	for {
		// 检查 done 通道（非阻塞）
		select {
		case <-x.done:
			logger.Info("[XDP] MonitorEvents exit")
			return
		default:
		}

		// 阻塞式读取 ringbuf 事件
		record, err := x.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[XDP] Ringbuf reader closed, trying to restart eBPF")
				x.Close()
				if err := x.Start(); err != nil {
					logger.Fatalf("[XDP] Failed to restart eBPF: %s", err.Error())
				}
				logger.Info("[XDP] eBPF restarted successfully, continuing to monitor")
				continue // 继续循环监听新事件
			}
			// 其他错误，检查 done 后继续
			select {
			case <-x.done:
				logger.Info("[XDP] MonitorEvents exit after error")
				return
			default:
				continue
			}
		}

		var pi PacketInfo
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pi); err != nil {
			logger.Warnf("[XDP] Failed to parse packet info: %v", err)
			continue
		}

		// 解析 IP 地址
		srcIP := formatIP(pi.SrcIP, pi.SrcIPv6, uint16(pi.EthProto))
		dstIP := formatIP(pi.DstIP, pi.DstIPv6, uint16(pi.EthProto))
		matchTypeStr := matchTypeToString(pi.MatchType)

		logger.Infof("[XDP] Blocked packet - Src: %s, MatchType: %s", srcIP, matchTypeStr)

		// 触发回调
		if x.callback != nil {
			// 从 eBPF map 查询规则来源
			ruleSource := x.getRuleSourceFromPacket(pi.SrcIP, pi.SrcIPv6, uint16(pi.EthProto), pi.MatchType)
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
	case MatchByWhitelist:
		return "whitelist"
	default:
		return "unknown"
	}
}

// getRuleSourceFromPacket 根据数据包信息从 eBPF map 中查询规则来源
// 通过 SrcIP 在 eBPF map 中查找 BlockValue 的 SourceMask，转换为来源名称
func (x *Xdp) getRuleSourceFromPacket(srcIP [4]byte, srcIPv6 [16]byte, ethProto uint16, mt MatchType) string {
	switch mt {
	case MatchByIP4Exact:
		var blockValue BlockValue
		if err := x.objects.BlockIpv4List.Lookup(&srcIP, &blockValue); err == nil {
			sources := MaskToSourceIDs(blockValue.SourceMask)
			if len(sources) > 0 {
				return sources[0]
			}
		}
	case MatchByIP4CIDR:
		// CIDR 匹配：使用 LPM trie lookup 查找最具体的匹配规则
		var blockValue BlockValue
		trieKey := IPv4TrieKey{PrefixLen: 32, Addr: srcIP}
		if err := x.objects.BlockIpv4CidrTrie.Lookup(&trieKey, &blockValue); err == nil {
			sources := MaskToSourceIDs(blockValue.SourceMask)
			if len(sources) > 0 {
				return sources[0]
			}
		}
	case MatchByIP6Exact:
		var blockValue BlockValue
		if err := x.objects.BlockIpv6List.Lookup(&srcIPv6, &blockValue); err == nil {
			sources := MaskToSourceIDs(blockValue.SourceMask)
			if len(sources) > 0 {
				return sources[0]
			}
		}
	case MatchByGeoBlock:
		return "geo"
	case MatchByMAC:
		return "manual"
	}
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
	logger.Debugf("[XDP] AddRule: bytes=%v, iptype=%v", bytes, iptype)
	// 手动规则设置 MANUAL 位 (0x04)
	blockValue := NewBlockValue(SourceMaskManual)
	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// DeleteRule 删除规则（完全删除，不论来源）
func (x *Xdp) DeleteRule(value string) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	// 传入空的 BlockValue 用于删除（实际不会使用）
	err = x.updateMap(iptype, bytes, BlockValue{}, false)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// AddRuleWithSource 添加指定来源的规则
func (x *Xdp) AddRuleWithSource(value string, sourceMask uint32) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	blockValue := NewBlockValue(sourceMask)
	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// AddRuleWithSourceAndExpiry 添加带过期时间的规则
// duration: 封禁时长（秒），0 表示永久封禁
func (x *Xdp) AddRuleWithSourceAndExpiry(value string, sourceMask uint32, duration int) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	blockValue := NewBlockValue(sourceMask)
	if duration > 0 {
		blockValue.Expiry = uint64(time.Now().Unix()) + uint64(duration)
	}
	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
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
			logger.Warnf("[XDP] Failed to parse value %s: %v", value, err)
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
			logger.Warnf("[XDP] Unsupported IP type: %v for value %s", iptype, value)
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

	x.updateFeatureFlags()
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
	// DeleteRule 已在每次成功删除后调用 updateFeatureFlags
	if len(errs) > 0 {
		return fmt.Errorf("batch delete failed with %d errors, first: %v", len(errs), errs[0])
	}
	return nil
}

// UpdateRuleSourceMask 更新规则的来源掩码（按位删除某个来源）
// value: IP/CIDR/MAC 地址
// removeMask: 要移除的来源位掩码
// 返回: 更新后的掩码, 规则是否存在, 是否有变化, 错误
func (x *Xdp) UpdateRuleSourceMask(value string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error) {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return 0, false, false, err
	}

	// 根据 IP 类型查询当前规则值
	var currentMask uint32
	var currentPriority uint32
	var currentExpiry uint64
	switch iptype {
	case utils.IPTypeIPv4:
		var key [4]byte
		copy(key[:], bytes)
		var blockValue BlockValue
		if err := x.objects.BlockIpv4List.Lookup(&key, &blockValue); err != nil {
			return 0, false, false, nil // 规则不存在
		}
		currentMask = blockValue.SourceMask
		currentPriority = blockValue.Priority
		currentExpiry = blockValue.Expiry
	case utils.IPTypeIPV4CIDR:
		var key IPv4TrieKey
		copy(key.Addr[:], bytes[4:])
		key.PrefixLen = binary.LittleEndian.Uint32(bytes[:4])
		var blockValue BlockValue
		if err := x.objects.BlockIpv4CidrTrie.Lookup(&key, &blockValue); err != nil {
			return 0, false, false, nil // 规则不存在
		}
		currentMask = blockValue.SourceMask
		currentPriority = blockValue.Priority
		currentExpiry = blockValue.Expiry
	case utils.IPTypeIPv6:
		var key [16]byte
		copy(key[:], bytes)
		var blockValue BlockValue
		if err := x.objects.BlockIpv6List.Lookup(&key, &blockValue); err != nil {
			return 0, false, false, nil // 规则不存在
		}
		currentMask = blockValue.SourceMask
		currentPriority = blockValue.Priority
		currentExpiry = blockValue.Expiry
	case utils.IPTypeIPv6CIDR:
		var key IPv6TrieKey
		copy(key.Addr[:], bytes[16:])
		key.PrefixLen = binary.LittleEndian.Uint32(bytes[:16])
		var blockValue BlockValue
		if err := x.objects.BlockIpv6CidrTrie.Lookup(&key, &blockValue); err != nil {
			return 0, false, false, nil // 规则不存在
		}
		currentMask = blockValue.SourceMask
		currentPriority = blockValue.Priority
		currentExpiry = blockValue.Expiry
	default:
		return 0, false, false, fmt.Errorf("unsupported IP type: %v", iptype)
	}

	// 计算新掩码: newMask = oldMask &^ removeMask
	newMask = currentMask &^ removeMask

	// 如果新掩码等于旧掩码，说明没有变化，跳过更新
	if newMask == currentMask {
		return currentMask, true, false, nil
	}

	// 如果新掩码为 0，删除规则
	if newMask == 0 {
		if err := x.DeleteRule(value); err != nil {
			return 0, true, true, fmt.Errorf("delete rule failed: %w", err)
		}
		return 0, true, true, nil
	}

	// 用新掩码更新规则，保留原有的 Priority 和 Expiry
	newBlockValue := NewBlockValueWithPreserve(newMask, currentPriority, currentExpiry)
	if err := x.updateMap(iptype, bytes, newBlockValue, true); err != nil {
		return currentMask, true, true, fmt.Errorf("update rule failed: %w", err)
	}

	return newMask, true, true, nil
}

// BatchUpdateRuleSourceMask 批量更新规则的来源掩码
// values: 要更新的规则列表
// removeMask: 要移除的来源位掩码
// 返回: 需要删除的规则列表（掩码变为 0 的规则），更新失败的错误
func (x *Xdp) BatchUpdateRuleSourceMask(values []string, removeMask uint32) ([]string, error) {
	var toDelete []string
	var errs []error

	for _, value := range values {
		newMask, exists, changed, err := x.UpdateRuleSourceMask(value, removeMask)
		if err != nil {
			errs = append(errs, fmt.Errorf("update %s failed: %w", value, err))
			continue
		}
		if exists && changed && newMask == 0 {
			// 掩码变为 0，规则已被删除
			toDelete = append(toDelete, value)
		}
	}

	if len(errs) > 0 {
		return toDelete, fmt.Errorf("batch update failed with %d errors, first: %v", len(errs), errs[0])
	}
	return toDelete, nil
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
			logger.Warnf("[GeoBlocking] Invalid format: %s", cidrWithCountry)
			continue
		}

		cidr := parts[0]
		countryCode := parts[1]

		// 解析 CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warnf("[GeoBlocking] Failed to parse CIDR %s: %v", cidr, err)
			continue
		}

		// 只处理 IPv4 网络（跳过 IPv6）
		if ipNet.IP.To4() == nil {
			logger.Debugf("[GeoBlocking] Skipping non-IPv4 network: %s", cidr)
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

// ============================================
// Event Reporting 相关方法
// ============================================

// SetEventConfig 设置事件上报配置
// enabled: 是否启用事件上报
// sampleRate: 采样率，每 N 个丢弃包上报 1 个 (例如 1000 = 0.1%)
func (x *Xdp) SetEventConfig(enabled bool, sampleRate uint32) error {
	config := NewEventConfig(enabled, sampleRate)
	key := uint32(0)
	return x.objects.EventConfig.Put(&key, &config)
}

// GetEventConfig 获取当前事件上报配置
func (x *Xdp) GetEventConfig() (EventConfig, error) {
	key := uint32(0)
	config := EventConfig{}
	if err := x.objects.EventConfig.Lookup(&key, &config); err != nil {
		// 如果查询失败（map 不存在），返回默认配置
		return DefaultEventConfig(), err
	}
	return config, nil
}

// IsEventReportingEnabled 检查事件上报是否启用
func (x *Xdp) IsEventReportingEnabled() bool {
	config, err := x.GetEventConfig()
	if err != nil {
		return false
	}
	return config.Enabled == 1
}

// ============================================
// Anomaly Detection 相关方法
// ============================================

// SetAnomalyConfig 设置异常检测采样配置
// enabled: 是否启用异常检测采样
// sampleRate: 采样率，每 N 个包采样 1 个 (例如 100 = 1%)
func (x *Xdp) SetAnomalyConfig(enabled bool, sampleRate uint32) error {
	config := NewAnomalyConfig(enabled, sampleRate)
	key := uint32(0)
	return x.objects.AnomalyConfig.Put(&key, &config)
}

// SetAnomalyPortFilter 设置异常检测端口过滤
// enabled: 是否启用端口过滤 (true=仅检测配置的端口, false=检测所有端口)
// ports: 需要检测的端口列表（同时应用于 TCP 和 UDP）
func (x *Xdp) SetAnomalyPortFilter(enabled bool, ports []uint32) error {
	// 更新配置中的 port_filter_enabled 标志
	key := uint32(0)
	config := AnomalyConfig{}
	if err := x.objects.AnomalyConfig.Lookup(&key, &config); err != nil {
		return err
	}

	if enabled && len(ports) > 0 {
		config.PortFilterEnabled = 1
	} else {
		config.PortFilterEnabled = 0
	}
	if err := x.objects.AnomalyConfig.Put(&key, &config); err != nil {
		return err
	}

	if config.PortFilterEnabled == 0 {
		// 清除之前设置的端口（ARRAY map 需要逐个清零）
		for _, oldPort := range x.anomalyPorts {
			zero := uint32(0)
			x.objects.AnomalyPorts.Put(&oldPort, &zero)
		}
		x.anomalyPorts = nil
		logger.Info("[XDP] Anomaly port filter disabled")
		return nil
	}

	// 清除旧端口，设置新端口（ARRAY map 需要显式清零旧条目）
	for _, oldPort := range x.anomalyPorts {
		zero := uint32(0)
		x.objects.AnomalyPorts.Put(&oldPort, &zero)
	}

	// 添加端口到 ARRAY map
	flag := uint32(1)
	for _, port := range ports {
		if err := x.objects.AnomalyPorts.Put(&port, &flag); err != nil {
			logger.Warnf("[XDP] Failed to add anomaly port %d: %v", port, err)
		}
	}
	x.anomalyPorts = make([]uint32, len(ports))
	copy(x.anomalyPorts, ports)

	logger.Infof("[XDP] Anomaly port filter enabled, ports: %v", ports)
	return nil
}

// GetAnomalyConfig 获取当前异常检测采样配置
func (x *Xdp) GetAnomalyConfig() (AnomalyConfig, error) {
	key := uint32(0)
	config := AnomalyConfig{}
	if err := x.objects.AnomalyConfig.Lookup(&key, &config); err != nil {
		// 如果查询失败（map 不存在），返回默认配置
		return DefaultAnomalyConfig(), err
	}
	return config, nil
}

// IsAnomalyDetectionEnabled 检查异常检测是否启用
func (x *Xdp) IsAnomalyDetectionEnabled() bool {
	config, err := x.GetAnomalyConfig()
	if err != nil {
		return false
	}
	return config.Enabled == 1
}

// ============================================
// IP Whitelist 相关方法
// 白名单优先级最高：命中白名单的 IP 直接 XDP_PASS
// ============================================

// WhitelistRule 白名单规则结构体
type WhitelistRule struct {
	Value   string    // IP/CIDR 值
	AddedAt time.Time // 添加时间
}

// updateWhitelistMap 更新白名单内核 map
// iptype: IP 类型
// value: 键值（字节数组）
// add: true=添加/更新, false=删除
func (x *Xdp) updateWhitelistMap(iptype utils.IPType, value []byte, add bool) error {
	blockValue := NewBlockValue(SourceMaskWhitelist)

	switch iptype {
	case utils.IPTypeIPv4:
		if add {
			return x.objects.WhitelistIpv4List.Put(value, blockValue)
		}
		return x.objects.WhitelistIpv4List.Delete(value)
	case utils.IPTypeIPV4CIDR:
		if add {
			return x.objects.WhitelistIpv4CidrTrie.Put(value, blockValue)
		}
		return x.objects.WhitelistIpv4CidrTrie.Delete(value)
	case utils.IPTypeIPv6:
		if add {
			return x.objects.WhitelistIpv6List.Put(value, blockValue)
		}
		return x.objects.WhitelistIpv6List.Delete(value)
	case utils.IPTypeIPv6CIDR:
		if add {
			return x.objects.WhitelistIpv6CidrTrie.Put(value, blockValue)
		}
		return x.objects.WhitelistIpv6CidrTrie.Delete(value)
	default:
		return fmt.Errorf("unsupported IP type for whitelist: %v", iptype)
	}
}

// AddWhitelistRule 添加白名单规则（支持 IP 和 CIDR，不支持 MAC）
func (x *Xdp) AddWhitelistRule(value string) error {
	value = strings.TrimSpace(value)
	b, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return fmt.Errorf("invalid whitelist value %s: %w", value, err)
	}
	// 白名单不支持 MAC 地址
	if iptype == utils.IPTypeMAC {
		return fmt.Errorf("whitelist does not support MAC addresses: %s", value)
	}
	logger.Debugf("[Whitelist] AddRule: value=%s, iptype=%v", value, iptype)
	err = x.updateWhitelistMap(iptype, b, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// DeleteWhitelistRule 删除白名单规则
func (x *Xdp) DeleteWhitelistRule(value string) error {
	value = strings.TrimSpace(value)
	b, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return fmt.Errorf("invalid whitelist value %s: %w", value, err)
	}
	logger.Debugf("[Whitelist] DeleteRule: value=%s, iptype=%v", value, iptype)
	err = x.updateWhitelistMap(iptype, b, false)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// GetWhitelistRules 获取所有白名单规则
func (x *Xdp) GetWhitelistRules() ([]string, error) {
	var rules []string

	// IPv4 精确匹配
	iter4 := x.objects.WhitelistIpv4List.Iterate()
	var key4 []byte
	var val4 BlockValue
	for iter4.Next(&key4, &val4) {
		if val4.SourceMask != 0 {
			ip := net.IP(key4)
			rules = append(rules, ip.String())
		}
	}
	if err := iter4.Err(); err != nil {
		return nil, fmt.Errorf("iterate whitelist ipv4 list failed: %w", err)
	}

	// IPv4 CIDR 匹配
	iter4Cidr := x.objects.WhitelistIpv4CidrTrie.Iterate()
	var key4Cidr IPv4TrieKey
	var val4Cidr BlockValue
	for iter4Cidr.Next(&key4Cidr, &val4Cidr) {
		if val4Cidr.SourceMask != 0 {
			ip := net.IP(key4Cidr.Addr[:])
			rules = append(rules, fmt.Sprintf("%s/%d", ip.String(), key4Cidr.PrefixLen))
		}
	}
	if err := iter4Cidr.Err(); err != nil {
		return nil, fmt.Errorf("iterate whitelist ipv4 cidr trie failed: %w", err)
	}

	// IPv6 精确匹配
	iter6 := x.objects.WhitelistIpv6List.Iterate()
	var key6 []byte
	var val6 BlockValue
	for iter6.Next(&key6, &val6) {
		if val6.SourceMask != 0 {
			ip := net.IP(key6)
			rules = append(rules, ip.String())
		}
	}
	if err := iter6.Err(); err != nil {
		return nil, fmt.Errorf("iterate whitelist ipv6 list failed: %w", err)
	}

	// IPv6 CIDR 匹配
	iter6Cidr := x.objects.WhitelistIpv6CidrTrie.Iterate()
	var key6Cidr IPv6TrieKey
	var val6Cidr BlockValue
	for iter6Cidr.Next(&key6Cidr, &val6Cidr) {
		if val6Cidr.SourceMask != 0 {
			ip := net.IP(key6Cidr.Addr[:])
			rules = append(rules, fmt.Sprintf("%s/%d", ip.String(), key6Cidr.PrefixLen))
		}
	}
	if err := iter6Cidr.Err(); err != nil {
		return nil, fmt.Errorf("iterate whitelist ipv6 cidr trie failed: %w", err)
	}

	return rules, nil
}

// AnomalyEventCallback 异常检测事件回调函数类型
// srcIP: 源 IP 地址
// protocol: 协议类型 (TCP=6, UDP=17, ICMP=1)
// tcpFlags: TCP 标志位
// pktSize: 数据包大小
type AnomalyEventCallback func(srcIP string, protocol uint8, tcpFlags uint8, pktSize uint32)

// MonitorAnomalyEvents 监听异常检测采样事件
// callback: 事件回调函数
// 此方法应该在单独的 goroutine 中运行
func (x *Xdp) MonitorAnomalyEvents(callback AnomalyEventCallback) {
	logger.Info("[XDP] MonitorAnomalyEvents started")
	
	// 创建独立的 Ring Buffer reader
	reader, err := ringbuf.NewReader(x.objects.AnomalyEvents)
	if err != nil {
		logger.Errorf("[XDP] Failed to create anomaly events reader: %v", err)
		return
	}
	defer reader.Close()
	
	for {
		// 检查 done 通道（非阻塞）
		select {
		case <-x.done:
			logger.Info("[XDP] MonitorAnomalyEvents exit")
			return
		default:
		}

		// 阻塞式读取 ringbuf 事件
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[XDP] Anomaly events ringbuf reader closed")
				return
			}
			// 其他错误，检查 done 后继续
			select {
			case <-x.done:
				logger.Info("[XDP] MonitorAnomalyEvents exit after error")
				return
			default:
				continue
			}
		}

		var pi PacketInfo
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pi); err != nil {
			logger.Warnf("[XDP] Failed to parse anomaly packet info: %v", err)
			continue
		}

		// 解析源 IP 地址（支持 IPv4 和 IPv6）
		srcIP := formatIP(pi.SrcIP, pi.SrcIPv6, uint16(pi.EthProto))

		// 触发回调
		if callback != nil {
			callback(srcIP, pi.IPProtocol, pi.TCPFlags, pi.PktSize)
		}
	}
}
