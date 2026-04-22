package anomaly

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/logger"

	"github.com/robfig/cron/v3"
)

// BlockCallback 封禁回调函数类型
// ip: 要封禁的 IP
// duration: 封禁时长（秒）
// reason: 封禁原因
type BlockCallback func(ip string, duration int, reason string) error

// UnblockCallback 解封回调函数类型
// ip: 要解封的 IP
type UnblockCallback func(ip string) error

// Manager 异常检测管理器
// 负责协调各个检测模块，管理协程生命周期
type Manager struct {
	config           AnomalyDetectionConfig
	collector        *Collector
	baselineDetector *BaselineDetector
	attackDetector   *AttackDetector
	blockCallback    BlockCallback
	unblockCallback  UnblockCallback

	mu        sync.RWMutex
	running   bool
	done      chan struct{}
	stopped   bool // 标志位，用于安全 Stop（避免重复 close channel）

	// 防止 runDetection 并发执行
	detectionMu sync.Mutex

	// Cron 定时任务
	cron *cron.Cron

	// 封禁记录管理（替代 time.AfterFunc）
	bannedIPs     map[string]time.Time // IP → 过期时间
	bannedIPsMu   sync.Mutex
}

// NewManager 创建新的异常检测管理器
// blockCallback: 封禁回调，当检测到攻击时调用
// unblockCallback: 解封回调，当封禁到期时调用
func NewManager(config AnomalyDetectionConfig, blockCallback BlockCallback, unblockCallback UnblockCallback) *Manager {
	// 设置默认值
	if config.CheckInterval == 0 {
		config.CheckInterval = 1
	}
	if config.MinPackets == 0 {
		config.MinPackets = 100
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 300
	}
	if config.SampleRate == 0 {
		config.SampleRate = 100
	}

	cleanupInterval := time.Duration(config.CleanupInterval) * time.Second
	maxAge := time.Duration(config.Baseline.MaxAge) * time.Second
	if cleanupInterval < maxAge {
		maxAge = cleanupInterval
	}

	return &Manager{
		config:           config,
		collector:        NewCollector(60, maxAge),
		baselineDetector: NewBaselineDetector(config.Baseline),
		attackDetector:   NewAttackDetector(config.Attacks),
		blockCallback:    blockCallback,
		unblockCallback:  unblockCallback,
		done:            make(chan struct{}),
		bannedIPs:       make(map[string]time.Time),
	}
}

// Start 启动异常检测器（支持 Restart：每次调用重置内部状态）
func (d *Manager) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	if !d.config.Enabled {
		logger.Info("[AnomalyDetection] Disabled, skipping start")
		return nil
	}

	logger.Info("[AnomalyDetection] Starting anomaly detection system")

	// 重置 done channel 和 stopped 标志（支持 Stop → Start 循环）
	d.done = make(chan struct{})
	d.stopped = false

	// 启动统计收集器（使用 CleanupInterval 控制清理间隔）
	d.collector.SetCleanupInterval(time.Duration(d.config.CleanupInterval) * time.Second)
	d.collector.Start()

	// 初始化 Cron 定时任务
	d.cron = cron.New(cron.WithSeconds())

	// 添加定时检测任务（根据配置的 CheckInterval）
	checkInterval := time.Duration(d.config.CheckInterval) * time.Second
	checkExpr := "@every " + checkInterval.String()
	_, err := d.cron.AddFunc(checkExpr, func() {
		d.runDetection()
		d.collector.UpdatePPS()
	})
	if err != nil {
		return fmt.Errorf("failed to add detection cron job: %w", err)
	}

	// 添加定时解封任务（每 5 分钟扫描一次）
	_, err = d.cron.AddFunc("@every 5m", func() {
		d.cleanupExpiredBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup cron job: %w", err)
	}

	// 启动定时任务
	d.cron.Start()

	d.running = true
	logger.Info("[AnomalyDetection] Started successfully")

	return nil
}

// Stop 停止异常检测器（可安全多次调用）
func (d *Manager) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	logger.Info("[AnomalyDetection] Stopping anomaly detection system")

	if !d.stopped {
		close(d.done)
		d.stopped = true
	}
	d.collector.Stop()

	// 停止 Cron 定时任务
	if d.cron != nil {
		d.cron.Stop()
	}

	d.running = false
	logger.Info("[AnomalyDetection] Stopped")
}

// RecordPacket 记录数据包（供外部调用）
func (d *Manager) RecordPacket(ip string, protocol uint8, tcpFlags uint8, pktSize uint32) {
	if !d.config.Enabled {
		return
	}
	d.collector.RecordPacket(ip, protocol, tcpFlags, pktSize)
}

// runDetection 执行检测
func (d *Manager) runDetection() {
	d.detectionMu.Lock()
	defer d.detectionMu.Unlock()

	allStats := d.collector.GetAllStats()

	for ip, stats := range allStats {
		// 1. 攻击类型检测（使用当前秒窗口的协议统计）
		attackResults := d.attackDetector.DetectAttack(&stats.ProtocolStats, d.config.MinPackets)
		for _, result := range attackResults {
			result.IP = ip
			d.handleDetection(result)
		}

		// 2. IQR 基线检测（使用当前 PPS）
		if len(attackResults) == 0 && stats.Window.CurrentPPS > 0 {
			// 获取原始基线数据进行检测（非深拷贝，通过 collector 直接访问）
			baseline, exists := d.collector.GetBaseline(ip)
			if !exists {
				continue
			}

			isAnomaly, threshold := d.baselineDetector.CheckAnomaly(baseline, float64(stats.Window.CurrentPPS))
			if isAnomaly {
				result := DetectionResult{
					IP:            ip,
					AttackType:    AttackTypeBaselineAnomaly,
					CurrentPPS:    stats.Window.CurrentPPS,
					Threshold:     threshold,
					BlockDuration: d.config.Baseline.BlockDuration,
					Timestamp:     time.Now(),
				}
				d.handleDetection(result)
			} else {
				// 更新基线（通过 collector 直接操作原始数据，避免写入深拷贝丢失）
				d.collector.UpdateBaseline(ip, func(bl *Baseline) {
					d.baselineDetector.UpdateBaseline(bl, stats.Window.PPSHistory, stats.Window.WindowSize)
				})
			}
		}
	}
}

// handleDetection 处理检测结果
func (d *Manager) handleDetection(result DetectionResult) {
	logger.Infof("[AnomalyDetection] Detected %s attack from %s, PPS=%d, threshold=%.2f, blocking for %ds",
		result.AttackType, result.IP, result.CurrentPPS, result.Threshold, result.BlockDuration)

	// 调用封禁回调
	if d.blockCallback != nil {
		reason := result.AttackType.String()
		if err := d.blockCallback(result.IP, result.BlockDuration, reason); err != nil {
			logger.Errorf("[AnomalyDetection] Failed to block IP %s: %v", result.IP, err)
		} else {
			logger.Infof("[AnomalyDetection] Successfully blocked IP %s for %ds", result.IP, result.BlockDuration)

			// 记录封禁时间和过期时间到 bannedIPs map
			if result.BlockDuration > 0 {
				d.bannedIPsMu.Lock()
				d.bannedIPs[result.IP] = time.Now().Add(time.Duration(result.BlockDuration) * time.Second)
				d.bannedIPsMu.Unlock()
			}
		}
	}

	// 从统计中移除已封禁的 IP（避免重复封禁）
	d.collector.RemoveIP(result.IP)
}

// cleanupExpiredBans 清理过期的封禁记录（定时任务）
func (d *Manager) cleanupExpiredBans() {
	d.bannedIPsMu.Lock()
	defer d.bannedIPsMu.Unlock()

	now := time.Now()
	for ip, expiry := range d.bannedIPs {
		if now.After(expiry) {
			// 调用解封回调
			if d.unblockCallback != nil {
				if err := d.unblockCallback(ip); err != nil {
					logger.Warnf("[AnomalyDetection] Failed to unblock IP %s: %v", ip, err)
				} else {
					logger.Infof("[AnomalyDetection] Successfully unblocked IP %s", ip)
				}
			}
			// 从 map 中移除
			delete(d.bannedIPs, ip)
		}
	}
}

// UpdateConfig 热更新异常检测动态配置
func (d *Manager) UpdateConfig(cfg AnomalyDetectionConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.config.Enabled = cfg.Enabled
	d.config.MinPackets = cfg.MinPackets
	d.config.Ports = cfg.Ports

	// 更新 baseline 配置
	d.config.Baseline = cfg.Baseline
	d.baselineDetector.UpdateConfig(cfg.Baseline)

	// 更新 attacks 配置
	d.config.Attacks = cfg.Attacks
	d.attackDetector.UpdateConfig(cfg.Attacks)

	logger.Infof("[AnomalyDetection] Config updated: enabled=%v, min_packets=%d, ports=%v",
		cfg.Enabled, cfg.MinPackets, cfg.Ports)
}

// GetConfig 获取当前异常检测配置（返回可动态化的字段）
func (d *Manager) GetConfig() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"enabled":         d.config.Enabled,
		"min_packets":     d.config.MinPackets,
		"ports":           d.config.Ports,
		"baseline":        d.config.Baseline,
		"attacks":         d.config.Attacks,
	}
}

// GetRawConfig 获取当前原始结构体配置（避免 map 类型断言失败问题）
func (d *Manager) GetRawConfig() AnomalyDetectionConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config
}

// GetStats 获取检测器统计信息
func (d *Manager) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        d.config.Enabled,
		"running":        d.running,
		"stats_count":    d.collector.GetStatsCount(),
		"sample_rate":    d.config.SampleRate,
		"check_interval": d.config.CheckInterval,
	}
}

// IsRunning 检查检测器是否正在运行
func (d *Manager) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// IsBanned 检查 IP 是否在封禁列表中（用于测试）
func (d *Manager) IsBanned(ip string) bool {
	d.bannedIPsMu.Lock()
	defer d.bannedIPsMu.Unlock()
	_, exists := d.bannedIPs[ip]
	return exists
}
