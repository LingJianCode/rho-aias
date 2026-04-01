// Package waf WAF 日志监控模块
// 监听 Caddy + Coraza WAF 日志，触发 IP 封禁并实现去重机制
package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"

	"github.com/robfig/cron/v3"
)

// sourceMaskWAF WAF 来源掩码，与 ebpfs.SourceMaskWAF (0x08) 保持一致
const sourceMaskWAF uint32 = 0x08

// sourceMaskRateLimit 频率限制来源掩码，与 ebpfs.SourceMaskRateLimit (0x20) 保持一致
const sourceMaskRateLimit uint32 = 0x20

// WAFLogEntry Caddy + Coraza WAF 审计日志结构
type WAFLogEntry struct {
	Transaction struct {
		ClientIP      string `json:"client_ip"`
		IsInterrupted bool   `json:"is_interrupted"`
	} `json:"transaction"`
}

// RateLimitLogEntry Caddy rate limit 日志结构
type RateLimitLogEntry struct {
	RemoteIP string `json:"remote_ip"`
	Msg      string `json:"msg"`
}

// Monitor WAF 日志监控器
type Monitor struct {
	cfg    *config.WAFConfig
	watcher *watcher.LogWatcher
	cron   *cron.Cron

	// 日志解析正则表达式
	ipRegex *regexp.Regexp
}

// NewMonitor 创建 WAF 日志监控器
func NewMonitor(cfg *config.WAFConfig, xdp watcher.XDPRuleManager, ctx context.Context) *Monitor {
	return &Monitor{
		cfg:     cfg,
		watcher: watcher.NewLogWatcher("WAF", "waf", xdp, ctx),
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

// Start 启动 WAF 日志监控
func (m *Monitor) Start() error {
	// 设置日志行处理回调
	m.watcher.SetLineHandler(m.handleLine)

	// 收集所有需要监听的日志文件路径
	var watchPaths []string
	if m.cfg.WAFLogPath != "" {
		watchPaths = append(watchPaths, m.cfg.WAFLogPath)
	}
	if m.cfg.RateLimitLogPath != "" {
		watchPaths = append(watchPaths, m.cfg.RateLimitLogPath)
	}

	// 设置文件过滤，只处理我们监听的文件
	watchedPaths := make([]string, len(watchPaths))
	copy(watchedPaths, watchPaths)
	originalHandler := m.watcher // 保存引用以注册 watch paths

	// 启动底层 watcher
	if err := originalHandler.Start(); err != nil {
		return err
	}

	// 注册日志文件监听
	for _, path := range watchPaths {
		if err := originalHandler.WatchLogFile(path); err != nil {
			logger.Warnf("[WAF] Failed to watch log: %v", err)
		}
	}

	// 初始化 Cron 定时任务
	m.cron = cron.New(cron.WithSeconds())

	// 添加定时清理任务（每 5 分钟）
	_, err := m.cron.AddFunc("@every 5m", func() {
		m.watcher.CleanupExpiredBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup cron job: %w", err)
	}

	// 启动定时任务
	m.cron.Start()

	logger.Infof("[WAF] Monitor started, ban_duration=%d seconds", m.cfg.BanDuration)

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
// 实现 watcher.LineHandler 接口
func (m *Monitor) handleLine(line string) (string, uint32, string, int, bool) {
	logSource := m.getLogSource(line)

	switch logSource {
	case "waf":
		ip := m.extractWAFIP(line)
		if ip == "" {
			return "", 0, "", 0, false
		}
		return ip, sourceMaskWAF, fmt.Sprintf("banned from waf log"), m.cfg.BanDuration, true

	case "rate_limit":
		ip := m.extractRateLimitIP(line)
		if ip == "" {
			return "", 0, "", 0, false
		}
		return ip, sourceMaskRateLimit, fmt.Sprintf("banned from rate_limit log"), m.cfg.BanDuration, true

	default:
		return "", 0, "", 0, false
	}
}

// getLogSource 根据日志行内容推断来源类型
// 通过 JSON 字段特征判断：WAF 日志包含 "transaction"，Rate limit 日志包含 "remote_ip"
func (m *Monitor) getLogSource(line string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		// 非 JSON 格式，根据当前监听的文件路径判断
		return "unknown"
	}

	// 快速检查 JSON 中的关键特征字段
	if strings.Contains(trimmed, `"transaction"`) {
		return "waf"
	}
	if strings.Contains(trimmed, `"remote_ip"`) || strings.Contains(trimmed, `"rate limit"`) {
		return "rate_limit"
	}
	return "unknown"
}

// extractWAFIP 从 WAF 审计日志行中提取 IP
// 只有 is_interrupted==true 时才封禁 client_ip
func (m *Monitor) extractWAFIP(line string) string {
	var entry WAFLogEntry
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

// extractRateLimitIP 从 Rate limit 日志行中提取 IP
func (m *Monitor) extractRateLimitIP(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "{") {
		var entry RateLimitLogEntry
		if err := json.Unmarshal([]byte(trimmed), &entry); err == nil && entry.RemoteIP != "" {
			return entry.RemoteIP
		}
	}
	// JSON 解析失败或非 JSON 格式，回退到正则匹配
	matches := m.ipRegex.FindAllString(line, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// extractIP 根据指定的日志来源类型从日志行中提取 IP 地址
// 用于日志解析和测试
func (m *Monitor) extractIP(line string, logSource string) string {
	switch logSource {
	case "waf":
		return m.extractWAFIP(line)
	case "rate_limit":
		return m.extractRateLimitIP(line)
	default:
		// 未知来源，取第一个 IP
		matches := m.ipRegex.FindAllString(line, -1)
		if len(matches) == 0 {
			return ""
		}
		return matches[0]
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
