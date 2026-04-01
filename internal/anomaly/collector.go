package anomaly

import (
	"sync"
	"time"

	"rho-aias/internal/logger"

	"github.com/robfig/cron/v3"
)

// Collector 统计收集器
// 负责收集和维护 IP 的统计信息，包括滑动窗口统计
type Collector struct {
	mu         sync.RWMutex
	statsMap   map[string]*IPStats // IP -> 统计数据
	windowSize int                 // 滑动窗口大小（秒）
	maxAge     time.Duration       // 统计数据最大存活时间
	cron       *cron.Cron
	done       chan struct{}
}

// NewCollector 创建新的统计收集器
// windowSize: 滑动窗口大小（秒）
// maxAge: 统计数据最大存活时间（超过此时间未活动的 IP 将被清理）
func NewCollector(windowSize int, maxAge time.Duration) *Collector {
	if windowSize <= 0 {
		windowSize = 60 // 默认 60 秒窗口
	}
	if maxAge <= 0 {
		maxAge = 5 * time.Minute // 默认 5 分钟
	}
	return &Collector{
		statsMap:   make(map[string]*IPStats),
		windowSize: windowSize,
		maxAge:     maxAge,
		done:       make(chan struct{}),
	}
}

// Start 启动收集器
func (c *Collector) Start() {
	// 初始化 Cron 定时任务
	c.cron = cron.New(cron.WithSeconds())

	// 添加定时清理任务
	cleanInterval := c.maxAge.String()
	if cleanInterval == "0s" {
		cleanInterval = "5m" // 默认 5 分钟
	}
	cleanExpr := "@every " + cleanInterval
	if _, err := c.cron.AddFunc(cleanExpr, func() {
		c.cleanup()
	}); err != nil {
		logger.Warnf("failed to add cleanup cron job: %v", err)
	}

	// 启动定时任务
	c.cron.Start()
}

// Stop 停止收集器
func (c *Collector) Stop() {
	close(c.done)
	if c.cron != nil {
		c.cron.Stop()
	}
}

// SetCleanupInterval 更新清理间隔
func (c *Collector) SetCleanupInterval(interval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxAge = interval
	// 注意：Cron 定时任务启动后无法动态修改间隔，需要重启
	// 这里仅更新 maxAge，实际清理间隔仍由启动时设置的任务决定
}

// RecordPacket 记录数据包
// ip: 源 IP 地址
// protocol: 协议类型 (TCP/UDP/ICMP)
// tcpFlags: TCP 标志位（仅 TCP 协议有效）
// pktSize: 数据包大小
func (c *Collector) RecordPacket(ip string, protocol uint8, tcpFlags uint8, pktSize uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	stats, exists := c.statsMap[ip]
	if !exists {
		stats = &IPStats{
			IP:        ip,
			FirstSeen: now,
			Window: SlidingWindow{
				PPSHistory: make([]uint64, c.windowSize),
				WindowSize: c.windowSize,
			},
		}
		c.statsMap[ip] = stats
	}

	// 更新当前秒窗口内的协议统计（每秒由 UpdatePPS 重置）
	stats.ProtocolStats.TotalPackets++
	stats.ProtocolStats.TotalBytes += uint64(pktSize)

	// 更新每秒包计数（用于 PPS 滑动窗口计算）
	stats.Window.PerSecondPackets++

	switch protocol {
	case ProtocolTCP:
		stats.ProtocolStats.TCPCount++
		if tcpFlags&TCPFlagSYN != 0 {
			stats.ProtocolStats.TCPSynCount++
		}
		if tcpFlags&TCPFlagACK != 0 {
			stats.ProtocolStats.TCPAckCount++
		}
		if tcpFlags&TCPFlagRST != 0 {
			stats.ProtocolStats.TCPRstCount++
		}
		if tcpFlags&TCPFlagFIN != 0 {
			stats.ProtocolStats.TCPFinCount++
		}
	case ProtocolUDP:
		stats.ProtocolStats.UDPCount++
	case ProtocolICMP:
		stats.ProtocolStats.ICMPCount++
	default:
		stats.ProtocolStats.OtherCount++
	}

	stats.LastUpdate = now
}

// UpdatePPS 更新 PPS（每秒包数）
// 此函数应该每秒调用一次，用于更新滑动窗口统计
func (c *Collector) UpdatePPS() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, stats := range c.statsMap {
		// 使用独立的每秒包计数作为当前秒的 PPS
		stats.Window.CurrentPPS = stats.Window.PerSecondPackets

		// 更新历史数据
		stats.Window.PPSHistory[stats.Window.PPSIndex] = stats.Window.CurrentPPS
		stats.Window.PPSIndex = (stats.Window.PPSIndex + 1) % stats.Window.WindowSize

		// 计算平均 PPS
		var sum uint64
		for _, pps := range stats.Window.PPSHistory {
			sum += pps
		}
		stats.Window.AvgPPS = float64(sum) / float64(stats.Window.WindowSize)

		// 重置每秒计数和当前秒窗口的协议统计（为下一秒做准备）
		stats.Window.PerSecondPackets = 0
		stats.ProtocolStats.Reset()
	}
}

// GetStats 获取指定 IP 的统计信息（深拷贝）
func (c *Collector) GetStats(ip string) (*IPStats, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats, exists := c.statsMap[ip]
	if !exists {
		return nil, false
	}
	return deepCopyIPStats(stats), true
}

// GetAllStats 获取所有 IP 的统计信息（深拷贝）
func (c *Collector) GetAllStats() map[string]*IPStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]*IPStats, len(c.statsMap))
	for ip, stats := range c.statsMap {
		result[ip] = deepCopyIPStats(stats)
	}
	return result
}

// UpdateBaseline 更新指定 IP 的基线数据（直接操作原始数据，非深拷贝）
func (c *Collector) UpdateBaseline(ip string, updateFn func(*Baseline)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats, exists := c.statsMap[ip]
	if exists {
		updateFn(&stats.Baseline)
	}
}

// GetBaseline 获取指定 IP 的基线数据深拷贝
func (c *Collector) GetBaseline(ip string) (*Baseline, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats, exists := c.statsMap[ip]
	if !exists {
		return nil, false
	}
	b := stats.Baseline
	return &b, true
}

// deepCopyIPStats 深拷贝 IPStats，避免切片共享底层数组导致的数据竞争
func deepCopyIPStats(stats *IPStats) *IPStats {
	cp := *stats
	// 深拷贝 PPSHistory 切片，避免与 UpdatePPS 的写入产生数据竞争
	cp.Window.PPSHistory = make([]uint64, stats.Window.WindowSize)
	copy(cp.Window.PPSHistory, stats.Window.PPSHistory)
	return &cp
}

// RemoveIP 移除指定 IP 的统计信息
func (c *Collector) RemoveIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.statsMap, ip)
}

// cleanup 清理过期的统计数据
func (c *Collector) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for ip, stats := range c.statsMap {
		if now.Sub(stats.LastUpdate) > c.maxAge {
			delete(c.statsMap, ip)
		}
	}
}

// GetStatsCount 获取当前统计的 IP 数量
func (c *Collector) GetStatsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.statsMap)
}
