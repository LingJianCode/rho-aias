// Package ratelimit Rate Limit 日志监控模块
// 监听 Caddy rate limit 日志，触发 IP 封禁并实现去重机制
package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"
	"rho-aias/utils"

	"github.com/robfig/cron/v3"
)

// LogEntry Caddy rate limit 日志结构
type LogEntry struct {
	RemoteIP string `json:"remote_ip"`
	Msg      string `json:"msg"`
}

// Manager Rate Limit 日志管理器
type Manager struct {
	mu sync.RWMutex

	cfg     *config.RateLimitConfig
	watcher *watcher.LogWatcher
	cron    *cron.Cron
	running bool

	// 日志解析正则表达式
	ipRegex *regexp.Regexp
}

// NewManager 创建 Rate Limit 日志管理器
func NewManager(cfg *config.RateLimitConfig, xdp watcher.XDPRuleManager, ctx context.Context,
	offsetStore *watcher.OffsetStore, banRecordStore watcher.BanRecordStore, whitelistCheck func(ip string) bool) *Manager {
	w := watcher.NewLogWatcher("RateLimit", "rate_limit", xdp, ctx)
	w.SetOffsetStore(offsetStore)
	w.SetBanRecordStore(banRecordStore)
	w.SetWhitelistCheck(whitelistCheck)
	return &Manager{
		cfg:     cfg,
		watcher: w,
		ipRegex: regexp.MustCompile(utils.IPv4RegexPattern),
	}
}

// Start 启动 Rate Limit 日志监控
func (m *Manager) Start() error {
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
	m.running = true

	logger.Infof("[RateLimit] Monitor started, ban_duration=%d seconds, log_path=%s", m.cfg.BanDuration, logPath)
	return nil
}

// Stop 停止监控
func (m *Manager) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.watcher.Stop()
	m.running = false
	logger.Info("[RateLimit] Monitor stopped")
}

// handleLine 处理一行日志，返回是否需要封禁
func (m *Manager) handleLine(line string) (string, uint32, string, int, bool) {
	ip := m.extractIP(line)
	if ip == "" {
		return "", 0, "", 0, false
	}
	return ip, ebpfs.SourceMaskRateLimit, "banned from rate_limit log", m.cfg.BanDuration, true
}

// extractIP 从 Rate limit 日志行中提取 IP
func (m *Manager) extractIP(line string) string {
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

// UpdateConfig 热更新 RateLimit 动态配置
func (m *Manager) UpdateConfig(enabled bool, banDuration int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg.Enabled = enabled
	m.cfg.BanDuration = banDuration
	logger.Infof("[RateLimit] Config updated: enabled=%v, ban_duration=%d", enabled, banDuration)
}

// GetConfig 获取当前 RateLimit 配置（返回可动态化的字段）
func (m *Manager) GetConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"enabled":      m.cfg.Enabled,
		"ban_duration": m.cfg.BanDuration,
	}
}

// GetBannedIPs 获取当前已封禁的 IP 列表
func (m *Manager) GetBannedIPs() []string {
	return m.watcher.GetBannedIPs()
}

// GetBanCount 获取当前封禁的 IP 数量
func (m *Manager) GetBanCount() int {
	return m.watcher.GetBanCount()
}

// IsBanned 检查 IP 是否被封禁
func (m *Manager) IsBanned(ip string) bool {
	return m.watcher.IsBanned(ip)
}

// IsRunning 检查监控器是否正在运行
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}
