// Package waf WAF 日志监控模块
// 监听 Caddy + Coraza WAF 日志，触发 IP 封禁并实现去重机制
package waf

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

// LogEntry Caddy + Coraza WAF 审计日志结构
type LogEntry struct {
	Transaction struct {
		ClientIP      string `json:"client_ip"`
		IsInterrupted bool   `json:"is_interrupted"`
	} `json:"transaction"`
}

// Monitor WAF 日志监控器
type Monitor struct {
	mu sync.RWMutex

	cfg     *config.WAFConfig
	watcher *watcher.LogWatcher
	cron    *cron.Cron

	// 日志解析正则表达式
	ipRegex *regexp.Regexp
}

// NewMonitor 创建 WAF 日志监控器
func NewMonitor(cfg *config.WAFConfig, xdp watcher.XDPRuleManager, ctx context.Context) *Monitor {
	return &Monitor{
		cfg:     cfg,
		watcher: watcher.NewLogWatcher("WAF", "waf", xdp, ctx),
		ipRegex: regexp.MustCompile(utils.IPv4RegexPattern),
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

// Start 启动 WAF 日志监控
func (m *Monitor) Start() error {
	m.watcher.SetLineHandler(m.handleLine)

	logPath := m.cfg.WAFLogPath
	if logPath == "" {
		logger.Warn("[WAF] No log path configured, monitor will not watch any files")
		return nil
	}

	if err := m.watcher.Start(); err != nil {
		return err
	}

	if err := m.watcher.WatchLogFile(logPath); err != nil {
		logger.Warnf("[WAF] Failed to watch log: %v", err)
	}

	m.cron = cron.New(cron.WithSeconds())
	_, err := m.cron.AddFunc("@every 5m", func() {
		m.watcher.CleanupExpiredBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup cron job: %w", err)
	}
	m.cron.Start()

	logger.Infof("[WAF] Monitor started, ban_duration=%d seconds, log_path=%s", m.cfg.BanDuration, logPath)
	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.watcher.Stop()
	logger.Info("[WAF] Monitor stopped")
}

// handleLine 处理一行日志，返回是否需要封禁
func (m *Monitor) handleLine(line string) (string, uint32, string, int, bool) {
	ip := m.extractIP(line)
	if ip == "" {
		return "", 0, "", 0, false
	}
	return ip, ebpfs.SourceMaskWAF, "banned from waf log", m.cfg.BanDuration, true
}

// extractIP 从 WAF 审计日志行中提取 IP
// 只有 is_interrupted==true 时才封禁 client_ip
func (m *Monitor) extractIP(line string) string {
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// JSON 解析失败，尝试正则匹配（向后兼容）
		matches := m.ipRegex.FindAllString(line, -1)
		if len(matches) == 0 {
			return ""
		}
		if len(matches) > 1 {
			return matches[len(matches)-1]
		}
		return matches[0]
	}

	if !entry.Transaction.IsInterrupted {
		return ""
	}

	return entry.Transaction.ClientIP
}

// UpdateConfig 热更新 WAF 动态配置
func (m *Monitor) UpdateConfig(enabled bool, banDuration int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg.Enabled = enabled
	m.cfg.BanDuration = banDuration
	logger.Infof("[WAF] Config updated: enabled=%v, ban_duration=%d", enabled, banDuration)
}

// GetConfig 获取当前 WAF 配置（返回可动态化的字段）
func (m *Monitor) GetConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"enabled":      m.cfg.Enabled,
		"ban_duration": m.cfg.BanDuration,
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

// IsRunning 检查监控器是否正在运行
func (m *Monitor) IsRunning() bool {
	return m.cron != nil
}
