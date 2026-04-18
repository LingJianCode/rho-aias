package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"rho-aias/internal/logger"
	"rho-aias/utils"
	"sync"

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
	reader        *ringbuf.Reader
	done          chan struct{}
	doneOnce      sync.Once
	linkType      string
	callback      BlockLogCallback
	closeMu       sync.Mutex
	mapMu         sync.RWMutex
	anomalyPorts  []uint32 // 已配置的异常检测端口列表（用于 ARRAY 清理）
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
	x.closeMu.Lock()
	defer x.closeMu.Unlock()
	return x.startInternal()
}

// startInternal eBPF 启动的核心逻辑（不含 closeMu 加锁，供 Start 和 restart 复用）
func (x *Xdp) startInternal() error {
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
	x.reader, err = ringbuf.NewReader(x.objects.BlocklogEvents)
	if err != nil {
		x.closeResources()
		return fmt.Errorf("failed to create ringbuf reader: %s", err.Error())
	}
	x.done = make(chan struct{})

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
		x.closeResources()
		return errors.New("failed to attach XDP program")
	}
	return nil
}

func (x *Xdp) Close() {
	x.closeMu.Lock()
	defer x.closeMu.Unlock()
	logger.Info("[XDP] Close")
	x.doneOnce.Do(x.closeResources)
}

// closeResources 释放所有 eBPF 资源（不含锁保护，由 Close/restart 调用）
func (x *Xdp) closeResources() {
	if x.done != nil {
		close(x.done)
		x.done = nil
	}
	if x.reader != nil {
		x.reader.Close()
		x.reader = nil
	}
	if x.link != nil {
		(*x.link).Close()
		x.link = nil
	}
	if x.objects != nil {
		x.objects.Close()
		x.objects = nil
	}
}

// restart 安全地重启 eBPF：先清理现有资源，再重新加载
func (x *Xdp) restart() error {
	x.closeMu.Lock()
	defer x.closeMu.Unlock()
	x.closeResources()
	x.doneOnce = sync.Once{}
	return x.startInternal()
}

// ============================================
// Feature Flags 相关方法
// ============================================

const (
	featureWhitelist = 1 << 0
	featureBlacklist = 1 << 1
)

// updateFeatureFlags 扫描所有白名单/黑名单 map，更新 feature_flags 位图
func (x *Xdp) updateFeatureFlags() {
	if x.objects == nil {
		return
	}

	flags := uint32(0)

	if x.mapHasEntries(x.objects.WhitelistIpv4List) ||
		x.mapHasEntries(x.objects.WhitelistIpv4CidrTrie) {
		flags |= featureWhitelist
	}

	if x.mapHasEntries(x.objects.BlockIpv4List) ||
		x.mapHasEntries(x.objects.BlockIpv4CidrTrie) {
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

// ============================================
// 事件监控
// ============================================

func (x *Xdp) MonitorBlockLogEvents() {
	logger.Info("[XDP] MonitorBlockLogEvents started")
	for {
		select {
		case <-x.done:
			logger.Info("[XDP] MonitorBlockLogEvents exit")
			return
		default:
		}

		record, err := x.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[XDP] Ringbuf reader closed, trying to restart eBPF")
				if err := x.restart(); err != nil {
					logger.Errorf("[XDP] Failed to restart eBPF: %s", err.Error())
					return
				}
				logger.Info("[XDP] eBPF restarted successfully, continuing to monitor")
				continue
			}
			select {
			case <-x.done:
				logger.Info("[XDP] MonitorBlockLogEvents exit after error")
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

		srcIP := formatIP(pi.SrcIP, uint16(pi.EthProto))
		dstIP := formatIP(pi.DstIP, uint16(pi.EthProto))
		matchTypeStr := matchTypeToString(pi.MatchType)

		logger.Infof("[XDP] Blocked packet - Src: %s, MatchType: %s", srcIP, matchTypeStr)

		if x.callback != nil {
			ruleSource := x.getRuleSourceFromPacket(pi.SrcIP, uint16(pi.EthProto), pi.MatchType)
			countryCode := ""
			x.callback(srcIP, dstIP, matchTypeStr, ruleSource, countryCode, pi.PktSize)
		}
	}
}

// formatIP 格式化 IP 地址（仅支持 IPv4）
func formatIP(ipv4 [4]byte, ethProto uint16) string {
	if ethProto == 0x0800 { // ETH_P_IP
		addr := netip.AddrFrom4(ipv4)
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
	case MatchByGeoBlock:
		return "geo_block"
	case MatchByWhitelist:
		return "whitelist"
	default:
		return "unknown"
	}
}

// getRuleSourceFromPacket 根据数据包信息从 eBPF map 中查询规则来源
func (x *Xdp) getRuleSourceFromPacket(srcIP [4]byte, ethProto uint16, mt MatchType) string {
	x.mapMu.RLock()
	defer x.mapMu.RUnlock()

	// 防护：restart() 期间 x.objects 可能被临时置为 nil
	if x.objects == nil {
		return "unknown"
	}

	switch mt {
	case MatchByIP4Exact:
		var blockValue BlockValue
		if x.objects.BlockIpv4List.Lookup(&srcIP, &blockValue) == nil {
			sources := MaskToSourceIDs(blockValue.SourceMask)
			if len(sources) > 0 {
				return sources[0]
			}
		}
	case MatchByIP4CIDR:
		var blockValue BlockValue
		trieKey := IPv4TrieKey{PrefixLen: 32, Addr: srcIP}
		if x.objects.BlockIpv4CidrTrie.Lookup(&trieKey, &blockValue) == nil {
			sources := MaskToSourceIDs(blockValue.SourceMask)
			if len(sources) > 0 {
				return sources[0]
			}
		}
	case MatchByGeoBlock:
		return "geo"
	}
	return "unknown"
}

// ============================================
// IP Whitelist 相关方法
// ============================================

// updateWhitelistMap 更新白名单内核 map
func (x *Xdp) updateWhitelistMap(iptype utils.IPType, value []byte, add bool) error {
	blockValue := NewBlockValue(0xFFFFFFFF)

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
	default:
		return fmt.Errorf("unsupported IP type for whitelist: %v", iptype)
	}
}

// AddWhitelistRule 添加白名单规则（支持 IPv4 和 CIDR）
func (x *Xdp) AddWhitelistRule(value string) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	value = strings.TrimSpace(value)
	b, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return fmt.Errorf("invalid whitelist value %s: %w", value, err)
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
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

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
	x.mapMu.RLock()
	defer x.mapMu.RUnlock()

	var rules []string

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

	return rules, nil
}

// AnomalyEventCallback 异常检测事件回调函数类型
type AnomalyEventCallback func(srcIP string, protocol uint8, tcpFlags uint8, pktSize uint32)

// MonitorAnomalyEvents 监听异常检测采样事件
// extraDone 为可选的额外停止信号（如禁用异常检测时触发），nil 则仅监听 x.done
func (x *Xdp) MonitorAnomalyEvents(callback AnomalyEventCallback, extraDone <-chan struct{}) {
	logger.Info("[XDP] MonitorAnomalyEvents started")

	reader, err := ringbuf.NewReader(x.objects.AnomalyEvents)
	if err != nil {
		logger.Errorf("[XDP] Failed to create anomaly events reader: %v", err)
		return
	}
	defer reader.Close()

	for {
		select {
		case <-x.done:
			logger.Info("[XDP] MonitorAnomalyEvents exit")
			return
		case <-extraDone:
			logger.Info("[XDP] MonitorAnomalyEvents exit (extra stop signal)")
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[XDP] Anomaly events ringbuf reader closed")
				return
			}
			select {
			case <-x.done:
				logger.Info("[XDP] MonitorAnomalyEvents exit after error")
				return
			case <-extraDone:
				logger.Info("[XDP] MonitorAnomalyEvents exit after error (extra stop signal)")
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

		srcIP := formatIP(pi.SrcIP, uint16(pi.EthProto))

		if callback != nil {
			callback(srcIP, pi.IPProtocol, pi.TCPFlags, pi.PktSize)
		}
	}
}
