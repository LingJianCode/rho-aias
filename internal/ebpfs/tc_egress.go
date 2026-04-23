package ebpfs

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"rho-aias/internal/logger"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/robfig/cron/v3"
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
		Enabled:    0, // 默认关闭
		RateBytes:  12500000,  // 100Mbps (100 * 10^6 / 8)
		BurstBytes: 125000,    // 125KB (约 10ms 缓冲)
	}
}

// 清理配置常量
const (
	// flowExpireThreshold 流过期阈值
	// 超过此时间未更新的流将被清理，等同于 LRU 的淘汰效果
	flowExpireThreshold = 5 * time.Minute

	// flowCleanupInterval 清理间隔
	flowCleanupInterval = "@every 1m"
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
	cron          *cron.Cron       // 定时清理过期流条目
	done          chan struct{}
	doneOnce      sync.Once
	closeMu       sync.Mutex
	mapMu         sync.RWMutex
}

// NewTcEgress 创建新的 TcEgress 实例
func NewTcEgress(interfaceName string) *TcEgress {
	return &TcEgress{
		InterfaceName: interfaceName,
	}
}

// Start 启动 TC egress 程序
func (t *TcEgress) Start() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	return t.startInternal()
}

// startInternal 启动逻辑（不含锁，供 Start 复用）
func (t *TcEgress) startInternal() error {
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

	// 初始化默认配置（关闭状态）
	if err := t.SetEgressLimitConfig(DefaultEgressLimitConfig()); err != nil {
		t.closeResources()
		return fmt.Errorf("failed to initialize default config: %w", err)
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
	if t.objects != nil {
		if t.tcLink != nil {
			t.tcLink.Close()
			t.tcLink = nil
		}
		t.objects.Close()
		t.objects = nil
	}
}

// SetEgressLimitConfig 设置限速配置
func (t *TcEgress) SetEgressLimitConfig(cfg EgressLimitConfig) error {
	t.mapMu.Lock()
	defer t.mapMu.Unlock()

	if t.objects == nil || t.objects.EgressLimitConfig == nil {
		return errors.New("eBPF objects not initialized")
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
// 确保 unsafe.Sizeof() == 24 (8+8+4(lock)+4(padding))
type FlowLimitState struct {
	Tokens       uint64
	LastUpdateNs uint64
	Lock         uint32   // bpf_spin_lock (4 bytes)
	_            [4]byte  // padding to 24 bytes
}

// Ensure FlowLimitState size matches eBPF side
var _ [24]byte = [24]byte{}

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
