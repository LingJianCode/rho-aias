package anomaly

import (
	"sync"
	"time"
)

// Collector 统计收集器
// 负责收集和维护 IP 的统计信息，包括滑动窗口统计
type Collector struct {
	mu            sync.RWMutex
	statsMap      map[string]*IPStats // IP -> 统计数据
	windowSize    int                 // 滑动窗口大小（秒）
	cleanupTicker *time.Ticker
	done          chan struct{}
}

// NewCollector 创建新的统计收集器
func NewCollector(windowSize int) *Collector {
	if windowSize <= 0 {
		windowSize = 60 // 默认 60 秒窗口
	}
	return &Collector{
		statsMap:   make(map[string]*IPStats),
		windowSize: windowSize,
		done:       make(chan struct{}),
	}
}

// Start 启动收集器
func (c *Collector) Start() {
	c.cleanupTicker = time.NewTicker(60 * time.Second)
	go c.cleanupLoop()
}

// Stop 停止收集器
func (c *Collector) Stop() {
	close(c.done)
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}
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

	// 更新协议统计
	stats.ProtocolStats.TotalPackets++
	stats.ProtocolStats.TotalBytes += uint64(pktSize)

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

	now := time.Now()
	for ip, stats := range c.statsMap {
		// 计算当前秒的 PPS
		elapsed := now.Sub(stats.LastUpdate).Seconds()
		if elapsed >= 1.0 {
			// 如果超过 1 秒没有数据，PPS 为 0
			stats.Window.CurrentPPS = 0
		} else {
			// 否则使用当前累计的包数作为 PPS（简化计算）
			// 更精确的做法是使用差分计算
		}

		// 更新历史数据
		stats.Window.PPSHistory[stats.Window.PPSIndex] = stats.Window.CurrentPPS
		stats.Window.PPSIndex = (stats.Window.PPSIndex + 1) % stats.Window.WindowSize

		// 计算平均 PPS
		var sum uint64
		for _, pps := range stats.Window.PPSHistory {
			sum += pps
		}
		stats.Window.AvgPPS = float64(sum) / float64(stats.Window.WindowSize)

		// 重置当前秒的统计
		stats.ProtocolStats.Reset()

		// 使用 ip 变量避免编译器警告
		_ = ip
	}
}

// GetStats 获取指定 IP 的统计信息
func (c *Collector) GetStats(ip string) (*IPStats, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats, exists := c.statsMap[ip]
	if !exists {
		return nil, false
	}
	// 返回副本，避免外部修改
	copy := *stats
	return &copy, true
}

// GetAllStats 获取所有 IP 的统计信息
func (c *Collector) GetAllStats() map[string]*IPStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]*IPStats, len(c.statsMap))
	for ip, stats := range c.statsMap {
		copy := *stats
		result[ip] = &copy
	}
	return result
}

// RemoveIP 移除指定 IP 的统计信息
func (c *Collector) RemoveIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.statsMap, ip)
}

// cleanupLoop 定期清理过期数据
func (c *Collector) cleanupLoop() {
	for {
		select {
		case <-c.done:
			return
		case <-c.cleanupTicker.C:
			c.cleanup()
		}
	}
}

// cleanup 清理过期的统计数据
func (c *Collector) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	maxAge := 5 * time.Minute // 超过 5 分钟未活动的 IP 清理掉

	for ip, stats := range c.statsMap {
		if now.Sub(stats.LastUpdate) > maxAge {
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
