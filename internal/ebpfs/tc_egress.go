package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"rho-aias/internal/config"
	"rho-aias/internal/kernel"
	"rho-aias/internal/logger"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/robfig/cron/v3"
	netlink "github.com/vishvananda/netlink"
)

// EgressLimitConfig 限速配置结构体 (与 eBPF 侧 egress_limit_config 对齐)
type EgressLimitConfig struct {
	Enabled    uint32
	_          uint32 // padding
	RateBytes  uint64
	BurstBytes uint64
}

// DefaultEgressLimitConfig 返回默认限速配置
func DefaultEgressLimitConfig() EgressLimitConfig {
	return EgressLimitConfig{
		Enabled:    0,          // 默认关闭
		RateBytes:  12500000,   // 100Mbps (100 * 10^6 / 8)
		BurstBytes: 25000000,   // 25MB (约 2s 缓冲，TCP 友好)
	}
}

// EgressDropEventConfig 丢包事件上报配置 (与 eBPF 侧 egress_drop_event_config 对齐)
type EgressDropEventConfig struct {
	Enabled    uint32
	SampleRate uint32
	Padding    [2]uint32
}

// NewEgressDropEventConfig 创建丢包事件配置
func NewEgressDropEventConfig(enabled bool, sampleRate uint32) EgressDropEventConfig {
	enabledVal := uint32(0)
	if enabled {
		enabledVal = 1
	}
	if sampleRate == 0 {
		sampleRate = 100 // 默认采样率
	}
	return EgressDropEventConfig{
		Enabled:    enabledVal,
		SampleRate: sampleRate,
		Padding:    [2]uint32{0, 0},
	}
}

// DefaultEgressDropEventConfig 返回默认丢包事件配置
func DefaultEgressDropEventConfig() EgressDropEventConfig {
	return NewEgressDropEventConfig(false, 100)
}

// EgressDropInfo 丢包事件结构体 (与 eBPF 侧 egress_drop_info 对齐)
type EgressDropInfo struct {
	DstIP     uint32
	PktLen    uint32
	Tokens    uint64
	RateBytes uint64
}

// EgressDropCallback 丢包事件回调函数类型
type EgressDropCallback func(dstIP string, pktLen uint32, tokens uint64, rateBytes uint64)

// 清理配置常量
const (
	// flowExpireThreshold 流过期阈值
	// 超过此时间未更新的流将被清理，等同于 LRU 的淘汰效果
	flowExpireThreshold = 5 * time.Minute

	// flowCleanupInterval 清理间隔
	flowCleanupInterval = "@every 1m"

	// minBurstBytes burst 下限 (至少容纳一个 MTU)
	minBurstBytes = 1500
)

// tcLinkCloser 是 TC 链接的统一关闭接口
// link.Link（TCX）和 netlinkTCLink（传统 netlink TC）都满足此接口
type tcLinkCloser interface {
	Close() error
}

// TcEgress TC Egress 限速管理器
// 管理 TC eBPF egress 程序的生命周期和配置操作
type TcEgress struct {
	InterfaceName string
	objects       *tcEgressObjects
	tcLink        tcLinkCloser     // TCX link 或 netlink TC link 引用
	dropReader    *ringbuf.Reader  // 丢包事件 RingBuf reader
	cron          *cron.Cron       // 定时清理过期流条目
	done          chan struct{}
	doneOnce      sync.Once
	closeMu       sync.Mutex
	mapMu         sync.RWMutex
	dropCallback  EgressDropCallback // 丢包事件回调
}

// NewTcEgress 创建新的 TcEgress 实例
func NewTcEgress(interfaceName string) *TcEgress {
	return &TcEgress{
		InterfaceName: interfaceName,
	}
}

// Start 启动 TC egress 程序
// cfg: 启动时一次性写入 eBPF map 的配置，避免"先写默认值再覆盖"的时序风险
func (t *TcEgress) Start(cfg config.EgressLimitConfig) error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()

	// 清理残留 TC 程序（仅 netlink TC 路径，内核 < 6.6）
	if err := t.cleanupStaleTC(); err != nil {
		return fmt.Errorf("cleanup stale TC: %w", err)
	}

	return t.startInternal(cfg)
}

// startInternal 启动逻辑（不含锁，供 Start 复用）
func (t *TcEgress) startInternal(cfg config.EgressLimitConfig) error {
	iface, err := net.InterfaceByName(t.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", t.InterfaceName, err)
	}

	// 提升资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warnf("[TcEgress] Failed to remove memlock: %s", err.Error())
	}

	// 加载 eBPF 对象
	var ebpfObj tcEgressObjects
	if err := loadTcEgressObjects(&ebpfObj, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	t.objects = &ebpfObj

	// 一次性写入实际配置（不再使用 DefaultEgressLimitConfig）
	rateBytes := uint64(cfg.RateMbps * 1000000 / 8)
	egressCfg := EgressLimitConfig{
		RateBytes:  rateBytes,
		BurstBytes: cfg.BurstBytes,
	}
	if cfg.Enabled {
		egressCfg.Enabled = 1
	}
	if err := t.SetEgressLimitConfig(egressCfg); err != nil {
		t.closeResources()
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// 一次性写入丢包事件配置
	dropSampleRate := cfg.DropLogSampleRate
	if dropSampleRate == 0 {
		dropSampleRate = 100
	}
	if err := t.SetDropLogConfig(cfg.DropLogEnabled, dropSampleRate); err != nil {
		logger.Warnf("[TcEgress] Failed to initialize drop log config: %v", err)
	}

	// 创建 RingBuf reader
	t.dropReader, err = ringbuf.NewReader(t.objects.EgressDropEvents)
	if err != nil {
		t.closeResources()
		return fmt.Errorf("failed to create drop event ringbuf reader: %w", err)
	}

	// 尝试挂载 TC 程序
	t.done = make(chan struct{})

	// 优先使用 TCX (内核 6.6+) 挂载 egress 程序
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   t.objects.EgressLimit,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		// TCX 失败（内核 < 6.6），fallback 到传统 netlink TC
		logger.Warnf("[TcEgress] TCX attach failed (kernel < 6.6?): %v, falling back to netlink TC", err)

		nlLink, nlErr := attachTCViaNetlink(iface.Index, t.InterfaceName, t.objects.EgressLimit)
		if nlErr != nil {
			t.closeResources()
			return fmt.Errorf("failed to attach TC program (both TCX and netlink failed: TCX=%v, netlink=%v)", err, nlErr)
		}
		t.tcLink = nlLink
		logger.Infof("[TcEgress] Netlink TC program attached on interface %s (index %d)", t.InterfaceName, iface.Index)
	} else {
		t.tcLink = l
		logger.Infof("[TcEgress] TCX program attached successfully on interface %s (index %d)", t.InterfaceName, iface.Index)
	}

	// 启动定时清理过期流（替代 LRU 自动淘汰）
	t.cron = cron.New(cron.WithSeconds())
	if _, err := t.cron.AddFunc(flowCleanupInterval, func() {
		t.doCleanup()
	}); err != nil {
		logger.Warnf("[TcEgress] Failed to add cleanup cron job: %v", err)
	}
	t.cron.Start()

	return nil
}

// Close 关闭 TC egress 程序
func (t *TcEgress) Close() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	logger.Info("[TcEgress] Closing")
	t.doneOnce.Do(t.closeResources)
}

// closeResources 释放所有资源（不含锁保护）
func (t *TcEgress) closeResources() {
	if t.cron != nil {
		t.cron.Stop()
		t.cron = nil
	}
	if t.done != nil {
		close(t.done)
		t.done = nil
	}
	if t.dropReader != nil {
		t.dropReader.Close()
		t.dropReader = nil
	}
	if t.objects != nil {
		if t.tcLink != nil {
			t.tcLink.Close()
			t.tcLink = nil
		}
		t.objects.Close()
		t.objects = nil
	}
}

// cleanupStaleTC 清理指定网卡上可能残留的 egress TC 过滤规则
// 仅处理 netlink TC 路径（内核 < 6.6），TCX 路径无需清理
func (t *TcEgress) cleanupStaleTC() error {
	// 检查内核版本，>= 6.6 使用 TCX，无需清理 netlink TC
	kv, err := kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("get kernel version: %w", err)
	}
	if kv.AtLeast(kernel.Version{Major: 6, Minor: 6}) {
		return nil
	}

	// 获取网卡 netlink link
	link, err := netlink.LinkByName(t.InterfaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %s: %w", t.InterfaceName, err)
	}

	// 列出 egress 方向 filter，找到 Priority==1 的残留
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("list egress filters on %s: %w", t.InterfaceName, err)
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Priority == 1 {
			if err := netlink.FilterDel(bf); err != nil {
				return fmt.Errorf("delete stale egress filter on %s: %w", t.InterfaceName, err)
			}
			logger.Infof("[TcEgress] Stale egress filter cleaned from %s", t.InterfaceName)
		}
	}
	return nil
}

// SetEgressLimitConfig 设置限速配置
func (t *TcEgress) SetEgressLimitConfig(cfg EgressLimitConfig) error {
	t.mapMu.Lock()
	defer t.mapMu.Unlock()

	if t.objects == nil || t.objects.EgressLimitConfig == nil {
		return errors.New("eBPF objects not initialized")
	}

	// burst 下限校验: 至少容纳一个 MTU 包
	if cfg.BurstBytes < minBurstBytes {
		cfg.BurstBytes = minBurstBytes
		logger.Warnf("[TcEgress] BurstBytes too small (%d), adjusted to minimum %d", cfg.BurstBytes, minBurstBytes)
	}

	key := uint32(0)
	if err := t.objects.EgressLimitConfig.Put(&key, &cfg); err != nil {
		return fmt.Errorf("failed to set egress limit config: %w", err)
	}

	logger.Debugf("[TcEgress] Config updated: enabled=%v, rate=%d bytes/s, burst=%d bytes",
		cfg.Enabled == 1, cfg.RateBytes, cfg.BurstBytes)
	return nil
}

// GetEgressLimitConfig 获取当前限速配置
func (t *TcEgress) GetEgressLimitConfig() (EgressLimitConfig, error) {
	t.mapMu.RLock()
	defer t.mapMu.RUnlock()

	if t.objects == nil || t.objects.EgressLimitConfig == nil {
		return EgressLimitConfig{}, errors.New("eBPF objects not initialized")
	}

	key := uint32(0)
	var cfg EgressLimitConfig
	if err := t.objects.EgressLimitConfig.Lookup(&key, &cfg); err != nil {
		return EgressLimitConfig{}, fmt.Errorf("failed to get egress limit config: %w", err)
	}

	return cfg, nil
}

// SetDropLogConfig 设置丢包事件上报配置
func (t *TcEgress) SetDropLogConfig(enabled bool, sampleRate uint32) error {
	t.mapMu.Lock()
	defer t.mapMu.Unlock()

	if t.objects == nil || t.objects.EgressDropEventConfig == nil {
		return errors.New("eBPF objects not initialized")
	}

	config := NewEgressDropEventConfig(enabled, sampleRate)
	key := uint32(0)
	if err := t.objects.EgressDropEventConfig.Put(&key, &config); err != nil {
		return fmt.Errorf("failed to set drop log config: %w", err)
	}

	logger.Debugf("[TcEgress] Drop log config updated: enabled=%v, sample_rate=%d", enabled, sampleRate)
	return nil
}

// GetDropLogConfig 获取当前丢包事件上报配置
func (t *TcEgress) GetDropLogConfig() (EgressDropEventConfig, error) {
	t.mapMu.RLock()
	defer t.mapMu.RUnlock()

	if t.objects == nil || t.objects.EgressDropEventConfig == nil {
		return DefaultEgressDropEventConfig(), errors.New("eBPF objects not initialized")
	}

	key := uint32(0)
	var cfg EgressDropEventConfig
	if err := t.objects.EgressDropEventConfig.Lookup(&key, &cfg); err != nil {
		return DefaultEgressDropEventConfig(), fmt.Errorf("failed to get drop log config: %w", err)
	}

	return cfg, nil
}

// SetDropCallback 设置丢包事件回调函数
func (t *TcEgress) SetDropCallback(callback EgressDropCallback) {
	t.dropCallback = callback
}

// MonitorDropEvents 监控丢包事件 (应在独立 goroutine 中运行)
func (t *TcEgress) MonitorDropEvents() {
	if t.dropReader == nil {
		logger.Warn("[TcEgress] dropReader is nil, skipping MonitorDropEvents")
		return
	}
	logger.Info("[TcEgress] MonitorDropEvents started")
	for {
		select {
		case <-t.done:
			logger.Info("[TcEgress] MonitorDropEvents exit")
			return
		default:
		}

		record, err := t.dropReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[TcEgress] Drop event ringbuf reader closed")
				return
			}
			select {
			case <-t.done:
				logger.Info("[TcEgress] MonitorDropEvents exit after error")
				return
			default:
				continue
			}
		}

		var dropInfo EgressDropInfo
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &dropInfo); err != nil {
			logger.Warnf("[TcEgress] Failed to parse drop info: %v", err)
			continue
		}

		// 将网络字节序的 IP 转换为字符串
		dstIP := formatEgressDropIP(dropInfo.DstIP)

		logger.Debugf("[TcEgress] Drop event - DstIP: %s, PktLen: %d, Tokens: %d, Rate: %d",
			dstIP, dropInfo.PktLen, dropInfo.Tokens, dropInfo.RateBytes)

		if t.dropCallback != nil {
			t.dropCallback(dstIP, dropInfo.PktLen, dropInfo.Tokens, dropInfo.RateBytes)
		}
	}
}

// formatEgressDropIP 将网络字节序的 uint32 IP 转换为字符串
func formatEgressDropIP(ipNetOrder uint32) string {
	// 网络字节序 -> [4]byte -> netip.Addr
	var ipBytes [4]byte
	binary.LittleEndian.PutUint32(ipBytes[:], ipNetOrder)
	addr := netip.AddrFrom4(ipBytes)
	return addr.String()
}

// SetEnabled 快速设置开关状态
func (t *TcEgress) SetEnabled(enabled bool) error {
	cfg, err := t.GetEgressLimitConfig()
	if err != nil {
		cfg = DefaultEgressLimitConfig()
	}

	if enabled {
		cfg.Enabled = 1
	} else {
		cfg.Enabled = 0
	}

	return t.SetEgressLimitConfig(cfg)
}

// IsEnabled 检查是否启用
func (t *TcEgress) IsEnabled() bool {
	cfg, err := t.GetEgressLimitConfig()
	if err != nil {
		return false
	}
	return cfg.Enabled == 1
}

// SetRate 设置限速速率（Bytes/s）
// rateMbps 是 Mbps 单位，内部转换为 Bytes/s
func (t *TcEgress) SetRate(rateMbps float64) error {
	cfg, err := t.GetEgressLimitConfig()
	if err != nil {
		cfg = DefaultEgressLimitConfig()
	}

	// Mbps -> Bytes/s (除以 8)
	cfg.RateBytes = uint64(rateMbps * 1000000 / 8)
	return t.SetEgressLimitConfig(cfg)
}

// SetBurst 设置突发上限（Bytes）
func (t *TcEgress) SetBurst(burstBytes uint64) error {
	cfg, err := t.GetEgressLimitConfig()
	if err != nil {
		cfg = DefaultEgressLimitConfig()
	}

	cfg.BurstBytes = burstBytes
	return t.SetEgressLimitConfig(cfg)
}

// GetFlowCount 获取当前 Hash Map 中的流数量
// 通过遍历计数，适用于 HASH 类型 Map
func (t *TcEgress) GetFlowCount() (int, error) {
	t.mapMu.RLock()
	defer t.mapMu.RUnlock()

	if t.objects == nil || t.objects.EgressLimits == nil {
		return 0, errors.New("eBPF objects not initialized")
	}

	count := 0
	iter := t.objects.EgressLimits.Iterate()
	var key uint32
	var val FlowLimitState
	for iter.Next(&key, &val) {
		count++
	}
	if err := iter.Err(); err != nil {
		return count, err
	}

	return count, nil
}

// ClearAllFlows 清除所有限速状态（慎用，会中断现有流的平滑限速）
func (t *TcEgress) ClearAllFlows() error {
	t.mapMu.Lock()
	defer t.mapMu.Unlock()

	if t.objects == nil || t.objects.EgressLimits == nil {
		return errors.New("eBPF objects not initialized")
	}

	iter := t.objects.EgressLimits.Iterate()
	var key uint32
	var val FlowLimitState
	for iter.Next(&key, &val) {
		t.objects.EgressLimits.Delete(&key)
	}
	if err := iter.Err(); err != nil {
		return err
	}

	logger.Info("[TcEgress] All flow states cleared")
	return nil
}

// FlowLimitState 对齐 eBPF 侧 struct flow_limit_state
// 确保 unsafe.Sizeof() == 32 (8+8+8+4(lock)+4(padding))
type FlowLimitState struct {
	Tokens       uint64
	LastUpdateNs uint64
	Fractional   uint64
	Lock         uint32  // bpf_spin_lock (4 bytes)
	_            [4]byte // padding to 32 bytes
}

// Ensure FlowLimitState size matches eBPF side
var _ [32]byte = [32]byte{}

var _ = unsafe.Sizeof(FlowLimitState{})

// doCleanup 执行一次过期条目清理
// 替代 LRU_HASH 的自动淘汰机制
func (t *TcEgress) doCleanup() {
	t.mapMu.RLock()
	defer t.mapMu.RUnlock()

	if t.objects == nil || t.objects.EgressLimits == nil {
		return
	}

	now := uint64(time.Now().UnixNano())
	expireThreshold := uint64(flowExpireThreshold.Nanoseconds())

	var expiredKeys []uint32
	iter := t.objects.EgressLimits.Iterate()
	var key uint32
	var val FlowLimitState
	for iter.Next(&key, &val) {
		if now > val.LastUpdateNs && (now-val.LastUpdateNs) > expireThreshold {
			expiredKeys = append(expiredKeys, key)
		}
	}
	if err := iter.Err(); err != nil {
		logger.Warnf("[TcEgress] Cleanup iteration error: %v", err)
		return
	}

	// 删除过期条目
	deleted := 0
	for _, k := range expiredKeys {
		if err := t.objects.EgressLimits.Delete(&k); err == nil {
			deleted++
		}
	}

	if deleted > 0 {
		logger.Debugf("[TcEgress] Cleaned up %d expired flow entries", deleted)
	}
}
