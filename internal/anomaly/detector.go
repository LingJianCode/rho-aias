package anomaly

import (
	"sync"
	"time"

	"rho-aias/internal/logger"
)

// BlockCallback 封禁回调函数类型
// ip: 要封禁的 IP
// duration: 封禁时长（秒）
// reason: 封禁原因
type BlockCallback func(ip string, duration int, reason string) error

// Detector 异常检测器主结构
// 负责协调各个检测模块，管理协程生命周期
type Detector struct {
	config           AnomalyDetectionConfig
	collector        *Collector
	baselineDetector *BaselineDetector
	attackDetector   *AttackDetector
	blockCallback    BlockCallback

	mu              sync.RWMutex
	running         bool
	done            chan struct{}
	ppsTicker       *time.Ticker
	cleanupTicker   *time.Ticker
	checkTicker     *time.Ticker
}

// NewDetector 创建新的异常检测器
func NewDetector(config AnomalyDetectionConfig, blockCallback BlockCallback) *Detector {
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
	if config.BlockDuration == 0 {
		config.BlockDuration = 60
	}
	if config.SampleRate == 0 {
		config.SampleRate = 100
	}

	// 基线配置默认值
	if config.Baseline.MinSampleCount == 0 {
		config.Baseline.MinSampleCount = 10
	}
	if config.Baseline.SigmaMultiplier == 0 {
		config.Baseline.SigmaMultiplier = 3.0
	}
	if config.Baseline.MinThreshold == 0 {
		config.Baseline.MinThreshold = 100
	}
	if config.Baseline.MaxAge == 0 {
		config.Baseline.MaxAge = 1800
	}

	return &Detector{
		config:           config,
		collector:        NewCollector(60), // 60 秒滑动窗口
		baselineDetector: NewBaselineDetector(config.Baseline),
		attackDetector:   NewAttackDetector(config.Attacks),
		blockCallback:    blockCallback,
		done:             make(chan struct{}),
	}
}

// Start 启动异常检测器
func (d *Detector) Start() error {
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

	// 启动统计收集器
	d.collector.Start()

	// 启动定时器
	d.checkTicker = time.NewTicker(time.Duration(d.config.CheckInterval) * time.Second)
	d.cleanupTicker = time.NewTicker(time.Duration(d.config.CleanupInterval) * time.Second)
	d.ppsTicker = time.NewTicker(1 * time.Second) // 每秒更新 PPS

	// 启动检测协程
	go d.detectionLoop()
	go d.ppsUpdateLoop()
	go d.cleanupLoop()

	d.running = true
	logger.Info("[AnomalyDetection] Started successfully")

	return nil
}

// Stop 停止异常检测器
func (d *Detector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	logger.Info("[AnomalyDetection] Stopping anomaly detection system")

	close(d.done)
	d.collector.Stop()

	if d.checkTicker != nil {
		d.checkTicker.Stop()
	}
	if d.cleanupTicker != nil {
		d.cleanupTicker.Stop()
	}
	if d.ppsTicker != nil {
		d.ppsTicker.Stop()
	}

	d.running = false
	logger.Info("[AnomalyDetection] Stopped")
}

// RecordPacket 记录数据包（供外部调用）
func (d *Detector) RecordPacket(ip string, protocol uint8, tcpFlags uint8, pktSize uint32) {
	if !d.config.Enabled {
		return
	}
	d.collector.RecordPacket(ip, protocol, tcpFlags, pktSize)
}

// detectionLoop 检测循环
func (d *Detector) detectionLoop() {
	for {
		select {
		case <-d.done:
			return
		case <-d.checkTicker.C:
			d.runDetection()
		}
	}
}

// runDetection 执行检测
func (d *Detector) runDetection() {
	allStats := d.collector.GetAllStats()

	for ip, stats := range allStats {
		// 1. 攻击类型检测
		attackResults := d.attackDetector.DetectAttack(&stats.ProtocolStats, d.config.MinPackets)
		for _, result := range attackResults {
			result.IP = ip
			d.handleDetection(result)
		}

		// 2. 3σ 基线检测
		if len(attackResults) == 0 && stats.Window.CurrentPPS > 0 {
			isAnomaly, threshold := d.baselineDetector.CheckAnomaly(&stats.Baseline, float64(stats.Window.CurrentPPS))
			if isAnomaly {
				result := DetectionResult{
					IP:           ip,
					AttackType:   AttackTypeBaselineAnomaly,
					CurrentPPS:   stats.Window.CurrentPPS,
					Threshold:    threshold,
					BlockDuration: d.config.BlockDuration,
					Timestamp:    time.Now(),
				}
				d.handleDetection(result)
			} else {
				// 更新基线（只有在没有检测到攻击时才更新）
				d.baselineDetector.UpdateBaseline(&stats.Baseline, float64(stats.Window.CurrentPPS))
			}
		}
	}
}

// handleDetection 处理检测结果
func (d *Detector) handleDetection(result DetectionResult) {
	logger.Infof("[AnomalyDetection] Detected %s attack from %s, PPS=%d, threshold=%.2f, blocking for %ds",
		result.AttackType, result.IP, result.CurrentPPS, result.Threshold, result.BlockDuration)

	// 调用封禁回调
	if d.blockCallback != nil {
		reason := result.AttackType.String()
		if err := d.blockCallback(result.IP, result.BlockDuration, reason); err != nil {
			logger.Errorf("[AnomalyDetection] Failed to block IP %s: %v", result.IP, err)
		} else {
			logger.Infof("[AnomalyDetection] Successfully blocked IP %s for %ds", result.IP, result.BlockDuration)
		}
	}

	// 从统计中移除已封禁的 IP（避免重复封禁）
	d.collector.RemoveIP(result.IP)
}

// ppsUpdateLoop PPS 更新循环
func (d *Detector) ppsUpdateLoop() {
	for {
		select {
		case <-d.done:
			return
		case <-d.ppsTicker.C:
			d.collector.UpdatePPS()
		}
	}
}

// cleanupLoop 清理循环
func (d *Detector) cleanupLoop() {
	for {
		select {
		case <-d.done:
			return
		case <-d.cleanupTicker.C:
			d.cleanup()
		}
	}
}

// cleanup 清理过期数据
func (d *Detector) cleanup() {
	// 统计信息由 collector 自动清理
	// 这里可以添加其他清理逻辑
	logger.Debugf("[AnomalyDetection] Cleanup completed, current stats count: %d", d.collector.GetStatsCount())
}

// GetStats 获取检测器统计信息
func (d *Detector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        d.config.Enabled,
		"running":        d.running,
		"stats_count":    d.collector.GetStatsCount(),
		"sample_rate":    d.config.SampleRate,
		"check_interval": d.config.CheckInterval,
	}
}

// IsRunning 检查检测器是否正在运行
func (d *Detector) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}
