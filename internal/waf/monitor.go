// Package waf WAF 日志监控模块
// 监听 Caddy + Coraza WAF 日志，触发 IP 封禁并实现去重机制
package waf

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"

	"github.com/fsnotify/fsnotify"
)

// IPBanRecord IP 封禁记录
type IPBanRecord struct {
	BannedAt time.Time // 封禁时间
	Expiry   time.Time // 过期时间
}

// Monitor WAF 日志监控器
type Monitor struct {
	cfg        *config.WAFConfig
	xdp        *ebpfs.Xdp
	ctx        context.Context
	cancel     context.CancelFunc
	watcher    *fsnotify.Watcher
	fileHandle *os.File
	filePos    int64 // 文件读取位置

	// 已封禁 IP 缓存
	bannedIPs map[string]IPBanRecord
	mu       sync.RWMutex

	// 日志解析正则表达式
	// 常见的 WAF 日志格式：
	// 1. Caddy access log: "1.2.3.4 - - [date] \"GET /path\" status rule_id"
	// 2. Coraza WAF: "client_ip: 1.2.3.4, rule_id: 12345"
	// 3. Rate limit: "rate_limit_exceeded for 1.2.3.4"
	ipRegex *regexp.Regexp
}

// NewMonitor 创建 WAF 日志监控器
func NewMonitor(cfg *config.WAFConfig, xdp *ebpfs.Xdp, ctx context.Context) *Monitor {
	childCtx, cancel := context.WithCancel(ctx)

	return &Monitor{
		cfg:      cfg,
		xdp:      xdp,
		ctx:      childCtx,
		cancel:   cancel,
		bannedIPs: make(map[string]IPBanRecord),
		// 匹配常见 IP 地址格式 (IPv4)
		ipRegex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	}
}

// Start 启动 WAF 日志监控
func (m *Monitor) Start() error {
	// 初始化文件监听器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	m.watcher = watcher

	// 监听 WAF 审计日志
	if m.cfg.WAFLogPath != "" {
		if err := m.watchLogFile(m.cfg.WAFLogPath); err != nil {
			logger.Warnf("[WAF] Failed to watch WAF log: %v", err)
		}
	}

	// 监听 Rate Limit 日志
	if m.cfg.RateLimitLogPath != "" {
		if err := m.watchLogFile(m.cfg.RateLimitLogPath); err != nil {
			logger.Warnf("[WAF] Failed to watch rate limit log: %v", err)
		}
	}

	// 启动监控 goroutine
	go m.monitorLoop()

	logger.Infof("[WAF] Monitor started, ban_duration=%d seconds", m.cfg.BanDuration)

	// 启动过期清理 goroutine
	go m.cleanupExpiredBans()

	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	logger.Info("[WAF] Stopping monitor...")
	m.cancel()
	if m.watcher != nil {
		m.watcher.Close()
	}
	if m.fileHandle != nil {
		m.fileHandle.Close()
	}
	logger.Info("[WAF] Monitor stopped")
}

// watchLogFile 监听单个日志文件
func (m *Monitor) watchLogFile(filePath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logger.Warnf("[WAF] Log file does not exist, will monitor for creation: %s", filePath)
	}

	// 添加监听（监听文件所在目录，因为文件可能被重新创建）
	dirPath := filePath[:strings.LastIndex(filePath, "/")]
	if err := m.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", dirPath, err)
	}

	logger.Infof("[WAF] Watching log file: %s", filePath)
	return nil
}

// monitorLoop 监控循环
func (m *Monitor) monitorLoop() {
	for {
		select {
		case <-m.ctx.Done():
			logger.Info("[WAF] Monitor loop exit")
			return

		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// 检查是否是我们关心的日志文件
			if event.Op&fsnotify.Write == fsnotify.Write ||
			   event.Op&fsnotify.Create == fsnotify.Create {
				m.handleLogFileEvent(event.Name)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("[WAF] Watcher error: %v", err)
		}
	}
}

// handleLogFileEvent 处理日志文件事件
func (m *Monitor) handleLogFileEvent(filePath string) {
	// 确保是我们要监听的文件
	if filePath != m.cfg.WAFLogPath && filePath != m.cfg.RateLimitLogPath {
		return
	}

	// 读取文件新增内容
	if err := m.readLogFile(filePath); err != nil {
		logger.Errorf("[WAF] Failed to read log file %s: %v", filePath, err)
	}
}

// readLogFile 读取日志文件的新内容
func (m *Monitor) readLogFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// 文件不存在或无法打开，可能是刚创建的，尝试读取完整内容
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// 如果文件变小了，说明被轮转了，从头开始读取
	fileSize := fileInfo.Size()
	if fileSize < m.filePos {
		m.filePos = 0
	}

	// 从上次读取的位置开始读取
	if _, err := file.Seek(m.filePos, 0); err != nil {
		return err
	}

	// 逐行读取新增内容
	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// 提取 IP 并封禁
		if ip := m.extractIP(line); ip != "" {
			m.banIP(ip, filePath)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// 更新读取位置
	m.filePos = fileSize

	if lineCount > 0 {
		logger.Debugf("[WAF] Processed %d new lines from %s", lineCount, filePath)
	}

	return nil
}

// extractIP 从日志行中提取 IP 地址
func (m *Monitor) extractIP(line string) string {
	matches := m.ipRegex.FindAllString(line, -1)
	if len(matches) == 0 {
		return ""
	}

	// 如果有多个 IP，通常第一个是客户端 IP
	// 可以根据具体日志格式调整
	return matches[0]
}

// banIP 封禁 IP 地址（带去重）
func (m *Monitor) banIP(ip, logFile string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 检查是否已封禁
	if record, exists := m.bannedIPs[ip]; exists {
		// 如果还在封禁期内，跳过
		if now.Before(record.Expiry) {
			logger.Debugf("[WAF] IP %s already banned (expires at %v), skipping", ip, record.Expiry)
			return
		}
		// 如果已过期，可以重新封禁
		logger.Infof("[WAF] IP %s ban expired, re-banning", ip)
	}

	// 调用 XDP 添加封禁规则
	if err := m.xdp.AddRuleWithSource(ip, ebpfs.SourceMaskWAF); err != nil {
		logger.Errorf("[WAF] Failed to add XDP rule for IP %s: %v", ip, err)
		return
	}

	// 记录封禁
	expiry := now.Add(time.Duration(m.cfg.BanDuration) * time.Second)
	m.bannedIPs[ip] = IPBanRecord{
		BannedAt: now,
		Expiry:   expiry,
	}

	logger.Infof("[WAF] Banned IP %s (from %s, expires at %v)", ip, logFile, expiry)
}

// cleanupExpiredBans 定期清理过期的封禁记录
func (m *Monitor) cleanupExpiredBans() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("[WAF] Cleanup goroutine exit")
			return

		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup 清理过期的封禁记录
func (m *Monitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for ip, record := range m.bannedIPs {
		if now.After(record.Expiry) {
			delete(m.bannedIPs, ip)
			expiredCount++
			logger.Debugf("[WAF] Cleaned up expired ban for IP %s", ip)
		}
	}

	if expiredCount > 0 {
		logger.Infof("[WAF] Cleaned up %d expired IP bans", expiredCount)
	}
}

// GetBannedIPs 获取当前已封禁的 IP 列表
func (m *Monitor) GetBannedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	ips := make([]string, 0, len(m.bannedIPs))

	for ip, record := range m.bannedIPs {
		if now.Before(record.Expiry) {
			ips = append(ips, ip)
		}
	}

	return ips
}

// GetBanCount 获取当前封禁的 IP 数量
func (m *Monitor) GetBanCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0

	for _, record := range m.bannedIPs {
		if now.Before(record.Expiry) {
			count++
		}
	}

	return count
}

// IsBanned 检查 IP 是否被封禁
func (m *Monitor) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	record, exists := m.bannedIPs[ip]
	if !exists {
		return false
	}

	return now.Before(record.Expiry)
}
