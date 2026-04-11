package failguard

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"

	"github.com/robfig/cron/v3"
)



// Monitor FailGuard 日志监控器
type Monitor struct {
	cfg     *config.FailGuardConfig
	watcher *watcher.LogWatcher
	cron    *cron.Cron

	// FailGuard 特有的字段
	failRegex   []*regexp.Regexp
	ignoreRegex []*regexp.Regexp
	ignoreCIDRs []*net.IPNet

	// 失败计数器：IP → 失败时间戳列表（滑动窗口）
	failures map[string][]time.Time
	failMu   sync.Mutex
}

// NewMonitor 创建 FailGuard 日志监控器
func NewMonitor(cfg *config.FailGuardConfig, xdp watcher.XDPRuleManager, ctx context.Context) *Monitor {
	m := &Monitor{
		cfg:     cfg,
		watcher: watcher.NewLogWatcher("FailGuard", "failguard", xdp, ctx),
	}

	// 确定使用的正则：用户配置覆盖或使用内置默认值
	failPatterns := cfg.FailRegex
	if len(failPatterns) == 0 {
		failPatterns = GetFailRegexByMode(cfg.Mode)
	}
	ignorePatterns := cfg.IgnoreRegex
	if len(ignorePatterns) == 0 {
		ignorePatterns = DefaultSSHDIgnoreRegex
	}

	// 编译正则
	var err error
	m.failRegex, err = compileRegex(failPatterns)
	if err != nil {
		logger.Warnf("[FailGuard] Failed to compile fail regex: %v", err)
	}
	m.ignoreRegex, err = compileRegex(ignorePatterns)
	if err != nil {
		logger.Warnf("[FailGuard] Failed to compile ignore regex: %v", err)
	}

	// 解析忽略 IP/CIDR 列表
	for _, cidr := range cfg.IgnoreIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				logger.Warnf("[FailGuard] Invalid ignore IP/CIDR: %s", cidr)
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				network = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else {
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		m.ignoreCIDRs = append(m.ignoreCIDRs, network)
	}

	m.failures = make(map[string][]time.Time)

	return m
}

// SetOffsetStore 设置偏移量持久化存储（可选）
func (m *Monitor) SetOffsetStore(store *watcher.OffsetStore) {
	m.watcher.SetOffsetStore(store)
}

// SetBanRecordStore 设置封禁记录持久化存储
func (m *Monitor) SetBanRecordStore(store watcher.BanRecordStore) {
	m.watcher.SetBanRecordStore(store)
}

// SetWhitelistCheck 设置白名单检查函数
func (m *Monitor) SetWhitelistCheck(fn func(ip string) bool) {
	m.watcher.SetWhitelistCheck(fn)
}

// Start 启动 FailGuard 日志监控
func (m *Monitor) Start() error {
	if m.cfg.LogPath == "" {
		return fmt.Errorf("log_path is required")
	}

	// 设置日志行处理回调
	m.watcher.SetLineHandler(m.handleLine)

	// 启动底层 watcher
	if err := m.watcher.Start(); err != nil {
		return err
	}

	// 监听日志文件
	if err := m.watcher.WatchLogFile(m.cfg.LogPath); err != nil {
		return fmt.Errorf("failed to watch log file: %w", err)
	}

	// 初始化 Cron 定时任务
	m.cron = cron.New(cron.WithSeconds())

	// 添加定时清理封禁任务（每 5 分钟）
	_, err := m.cron.AddFunc("@every 5m", func() {
		m.watcher.CleanupExpiredBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup bans cron job: %w", err)
	}

	// 添加定时清理失败计数任务（每 1 分钟）— FailGuard 特有
	_, err = m.cron.AddFunc("@every 1m", func() {
		m.cleanupFailures()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup failures cron job: %w", err)
	}

	// 启动定时任务
	m.cron.Start()

	logger.Infof("[FailGuard] Monitor started, mode=%s, log=%s, max_retry=%d, find_time=%ds, ban_duration=%ds",
		m.cfg.Mode, m.cfg.LogPath, m.cfg.MaxRetry, m.cfg.FindTime, m.cfg.BanDuration)

	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.watcher.Stop()
	logger.Info("[FailGuard] Monitor stopped")
}

// handleLine 处理一行日志：ignore 检查 → fail 匹配 → 白名单 → 已封禁 → 滑动窗口计数
// 实现 watcher.LineHandler 接口
func (m *Monitor) handleLine(line string) (string, uint32, string, int, bool) {
	// 1. ignoreregex 匹配 → 跳过
	if m.matchIgnore(line) {
		return "", 0, "", 0, false
	}

	// 2. failregex 匹配 → 提取 IP
	ip := m.matchFail(line)
	if ip == "" {
		return "", 0, "", 0, false
	}

	// 3. 白名单跳过
	if m.isIgnoredIP(ip) {
		return "", 0, "", 0, false
	}

	// 4. 已封禁跳过
	if m.watcher.IsBanned(ip) {
		return "", 0, "", 0, false
	}

	// 5. 滑动窗口计数，达阈值则封禁
	if m.addFailureAndCheck(ip) {
		return ip, ebpfs.SourceMaskFailGuard, "SSH brute force", m.cfg.BanDuration, true
	}

	return "", 0, "", 0, false
}

// matchIgnore 检查行是否匹配忽略规则
func (m *Monitor) matchIgnore(line string) bool {
	for _, re := range m.ignoreRegex {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// matchFail 检查行是否匹配失败规则，返回提取的 IP
func (m *Monitor) matchFail(line string) string {
	for _, re := range m.failRegex {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 0 {
			// 优先查找命名捕获组 "host"
			for i, name := range re.SubexpNames() {
				if name == "host" && i < len(matches) && matches[i] != "" {
					return matches[i]
				}
			}
			// 回退：查找第一个看起来像 IP 的子匹配
			for i := 1; i < len(matches); i++ {
				if matches[i] != "" && net.ParseIP(matches[i]) != nil {
					return matches[i]
				}
			}
		}
	}
	return ""
}

// isIgnoredIP 检查 IP 是否在忽略列表中
func (m *Monitor) isIgnoredIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, network := range m.ignoreCIDRs {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// addFailureAndCheck 添加失败记录并检查是否达到阈值
func (m *Monitor) addFailureAndCheck(ip string) bool {
	m.failMu.Lock()
	defer m.failMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(m.cfg.FindTime) * time.Second)

	// 清理窗口外的旧记录
	var valid []time.Time
	for _, t := range m.failures[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	m.failures[ip] = valid

	return len(valid) >= m.cfg.MaxRetry
}

// cleanupFailures 清理过期的失败计数记录
func (m *Monitor) cleanupFailures() {
	m.failMu.Lock()
	defer m.failMu.Unlock()

	cutoff := time.Now().Add(-time.Duration(m.cfg.FindTime) * time.Second)
	count := 0
	for ip, attempts := range m.failures {
		var valid []time.Time
		for _, t := range attempts {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(m.failures, ip)
			count++
		} else if len(valid) != len(attempts) {
			m.failures[ip] = valid
		}
	}

	if count > 0 {
		logger.Debugf("[FailGuard] Cleaned up failure records for %d IPs", count)
	}
}

// UpdateConfig 热更新 FailGuard 动态配置
func (m *Monitor) UpdateConfig(enabled bool, maxRetry, findTime, banDuration int, mode string) {
	m.failMu.Lock()
	defer m.failMu.Unlock()

	m.cfg.Enabled = enabled
	m.cfg.MaxRetry = maxRetry
	m.cfg.FindTime = findTime
	m.cfg.BanDuration = banDuration
	if mode != "" {
		m.cfg.Mode = mode
	}

	logger.Infof("[FailGuard] Config updated: enabled=%v, max_retry=%d, find_time=%d, ban_duration=%d, mode=%s",
		enabled, maxRetry, findTime, banDuration, mode)
}

// GetConfig 获取当前 FailGuard 配置（返回可动态化的字段）
func (m *Monitor) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      m.cfg.Enabled,
		"max_retry":    m.cfg.MaxRetry,
		"find_time":    m.cfg.FindTime,
		"ban_duration": m.cfg.BanDuration,
		"mode":         m.cfg.Mode,
	}
}

// GetBannedIPs 获取当前已封禁的 IP 列表
func (m *Monitor) GetBannedIPs() []string {
	return m.watcher.GetBannedIPs()
}

// GetBanCount 获取当前封禁的 IP 数量
func (m *Monitor) GetBanCount() int {
	return m.watcher.GetBanCount()
}

// IsBanned 检查 IP 是否被封禁
func (m *Monitor) IsBanned(ip string) bool {
	return m.watcher.IsBanned(ip)
}
