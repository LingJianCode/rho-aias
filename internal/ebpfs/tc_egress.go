package ebpfs

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"rho-aias/internal/logger"

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

// TcEgress TC Egress 限速管理器
// 管理 TC eBPF egress 程序的生命周期和配置操作
type TcEgress struct {
	InterfaceName string
	objects       *tcEgressObjects
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

	// 使用 tc 命令挂载程序
	if err := t.attachWithTC(*iface); err != nil {
		t.closeResources()
		return fmt.Errorf("failed to attach TC program: %w", err)
	}

	logger.Infof("[TcEgress] Program attached successfully on interface %s", t.InterfaceName)

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

// getObjectFilePath 返回 bpf2go 生成的对象文件路径
func getObjectFilePath() (string, error) {
	// bpf2go 生成的文件在 ebpfs 目录下
	// 尝试常见的路径
	possiblePaths := []string{
		"ebpfs/tcEgress_bpfel.o",
		"ebpfs/tcEgress_bpfeb.o",
		"./ebpfs/tcEgress_bpfel.o",
		"./ebpfs/tcEgress_bpfeb.o",
	}

	for _, path := range possiblePaths {
		// 尝试绝对路径
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if _, err := exec.LookPath(absPath); err == nil {
			return absPath, nil
		}
	}

	return "", errors.New("TC egress object file not found, run 'go generate' first")
}

// attachWithTC 使用 tc 命令挂载 TC egress 程序
// 使用 clsact qdisc + bpf filter 方式
func (t *TcEgress) attachWithTC(iface net.Interface) error {
	ifaceName := iface.Name

	// 1. 添加 clsact qdisc (如果不存在则创建)
	cmd := exec.Command("tc", "qdisc", "show", "dev", ifaceName)
	output, _ := cmd.Output()
	if !strings.Contains(string(output), "clsact") {
		addQdisc := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
		if err := addQdisc.Run(); err != nil {
			logger.Warnf("[TcEgress] Failed to add clsact qdisc (may already exist): %v", err)
		}
	}

	// 2. 删除可能存在的旧 filter
	delCmd := exec.Command("tc", "filter", "del", "dev", ifaceName, "egress")
	delCmd.Run() // ignore error if no filter exists

	// 3. 获取对象文件路径
	oFile, err := getObjectFilePath()
	if err != nil {
		return err
	}

	// 4. 添加新的 bpf filter
	// 使用 prio 1 和 handle 1 作为标识
	addCmd := exec.Command("tc", "filter", "add", "dev", ifaceName, "egress",
		"prio", "1", "handle", "1",
		"bpf", "da", "obj", oFile, "sec", "tc")
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add tc filter: %w", err)
	}

	logger.Infof("[TcEgress] TC filter added: obj=%s", filepath.Base(oFile))
	return nil
}

// Detach 分离 TC egress 程序（清理 tc qdisc filter）
func (t *TcEgress) Detach() error {
	// 删除 bpf filter
	delCmd := exec.Command("tc", "filter", "del", "dev", t.InterfaceName, "egress")
	delCmd.Run() // ignore error

	logger.Infof("[TcEgress] TC filter detached from interface %s", t.InterfaceName)
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
		// 先分离 tc filter
		t.Detach()
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
