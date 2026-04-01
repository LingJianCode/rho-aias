// Package ratelimit Rate Limit 日志监控模块
// 监听 Caddy rate limit 日志，触发 IP 封禁并实现去重机制
package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"

	"github.com/robfig/cron/v3"
)

// LogEntry Caddy rate limit 日志结构
type LogEntry struct {
	RemoteIP string `json:"remote_ip"`
	Msg      string `json:"msg"`
}

// Monitor Rate Limit 日志监控器
type Monitor struct {
	cfg     *config.RateLimitConfig
	watcher *watcher.LogWatcher
	cron    *cron.Cron

	// 日志解析正则表达式
	ipRegex *regexp.Regexp
}

// NewMonitor 创建 Rate Limit 日志监控器
func NewMonitor(cfg *config.RateLimitConfig, xdp watcher.XDPRuleManager, ctx context.Context) *Monitor {
	return &Monitor{
		cfg:     cfg,
		watcher: watcher.NewLogWatcher("RateLimit", "rate_limit", xdp, ctx),
		ipRegex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	}
}

// SetBanRecordStore 设置封禁记录持久化存储
func (m *Monitor) SetBanRecordStore(store watcher.BanRecordStore) {
	m.watcher.SetBanRecordStore(store)
}

// SetOffsetStore 设置偏移量持久化存储（可选）
func (m *Monitor) SetOffsetStore(store *watcher.OffsetStore) {
	m.watcher.SetOffsetStore(store)
}

// SetWhitelistCheck 设置白名单检查函数
func (m *Monitor) SetWhitelistCheck(fn func(ip string) bool) {
	m.watcher.SetWhitelistCheck(fn)
}

// Start 启动 Rate Limit 日志监控
func (m *Monitor) Start() error {
	m.watcher.SetLineHandler(m.handleLine)

	logPath := m.cfg.LogPath
	if logPath == "" {
		logger.Warn("[RateLimit] No log path configured, monitor will not watch any files")
		return nil
	}

	if err := m.watcher.Start(); err != nil {
		return err
	}

	if err := m.watcher.WatchLogFile(logPath); err != nil {
		logger.Warnf("[RateLimit] Failed to watch log: %v", err)
	}

	m.cron = cron.New(cron.WithSeconds())
	_, err := m.cron.AddFunc("@every 5m", func() {
		m.watcher.CleanupExpiredBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup cron job: %w", err)
	}
	m.cron.Start()

	logger.Infof("[RateLimit] Monitor started, ban_duration=%d seconds, log_path=%s", m.cfg.BanDuration, logPath)
	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.watcher.Stop()
	logger.Info("[RateLimit] Monitor stopped")
}

// handleLine 处理一行日志，返回是否需要封禁
func (m *Monitor) handleLine(line string) (string, uint32, string, int, bool) {
	ip := m.extractIP(line)
	if ip == "" {
		return "", 0, "", 0, false
	}
	return ip, ebpfs.SourceMaskRateLimit, fmt.Sprintf("banned from rate_limit log"), m.cfg.BanDuration, true
}

// extractIP 从 Rate limit 日志行中提取 IP
func (m *Monitor) extractIP(line string) string {
	trimmed := json.RawMessage{}
	if err := json.Unmarshal([]byte(line), &trimmed); err == nil {
		var entry LogEntry
		if err := json.Unmarshal(trimmed, &entry); err == nil && entry.RemoteIP != "" {
			return entry.RemoteIP
		}
	}
	matches := m.ipRegex.FindAllString(line, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
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
