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
	maxAge        time.Duration       // 统计数据最大存活时间
	cleanupTicker *time.Ticker
	done          chan struct{}
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
	for _, stats := range c.statsMap {
		// 使用当前累计的包数作为当前秒的 PPS
		// RecordPacket 在当前秒内不断累加 TotalPackets
		// 在下一次 UpdatePPS 之前，TotalPackets 就是当前秒收到的包数
		stats.Window.CurrentPPS = stats.ProtocolStats.TotalPackets

		// 更新历史数据
		stats.Window.PPSHistory[stats.Window.PPSIndex] = stats.Window.CurrentPPS
		stats.Window.PPSIndex = (stats.Window.PPSIndex + 1) % stats.Window.WindowSize

		// 计算平均 PPS
		var sum uint64
		for _, pps := range stats.Window.PPSHistory {
			sum += pps
		}
		stats.Window.AvgPPS = float64(sum) / float64(stats.Window.WindowSize)

		// 重置当前秒的统计（为下一秒做准备）
		stats.ProtocolStats.Reset()

		_ = now // 避免未使用变量警告
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

// deepCopyIPStats 深拷贝 IPStats，避免切片共享底层数组导致的数据竞争
func deepCopyIPStats(stats *IPStats) *IPStats {
	copy := *stats
	// 深拷贝 PPSHistory 切片，避免与 UpdatePPS 的写入产生数据竞争
	copy.Window.PPSHistory = make([]uint64, stats.Window.WindowSize)
	copySlice(copy.Window.PPSHistory, stats.Window.PPSHistory)
	return &copy
}

// copySlice 将 src 切片拷贝到 dst 切片
func copySlice(dst, src []uint64) {
	minLen := len(dst)
	if len(src) < minLen {
		minLen = len(src)
	}
	for i := 0; i < minLen; i++ {
		dst[i] = src[i]
	}
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
