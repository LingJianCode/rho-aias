// Package waf WAF 日志监控模块
// 监听 Caddy + Coraza WAF 日志，触发 IP 封禁并实现去重机制
package waf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"

	"github.com/fsnotify/fsnotify"
	"github.com/robfig/cron/v3"
)

// syscallStatT 用于获取文件 inode
type syscallStatT = syscall.Stat_t

// sourceMaskWAF WAF 来源掩码，与 ebpfs.SourceMaskWAF (0x08) 保持一致
const sourceMaskWAF uint32 = 0x08

// sourceMaskRateLimit 频率限制来源掩码，与 ebpfs.SourceMaskRateLimit (0x20) 保持一致
const sourceMaskRateLimit uint32 = 0x20

// IPBanRecord IP 封禁记录
type IPBanRecord struct {
	BannedAt   time.Time // 封禁时间
	Expiry     time.Time // 过期时间
	SourceMask uint32    // 封禁来源掩码，用于清理时使用正确的 mask
}

// XDPRuleManager 定义 WAF Monitor 所需的 XDP 规则操作接口
// 通过接口抽象，方便单元测试中使用 mock 替代真实 XDP
type XDPRuleManager interface {
	AddRuleWithSource(ip string, sourceMask uint32) error
	UpdateRuleSourceMask(ip string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error)
}

// BanRecordStore 封禁记录持久化接口
type BanRecordStore interface {
	UpsertActiveBan(ip, source, reason string, duration int) error
	MarkExpired(ip, source string) error
}

// Monitor WAF 日志监控器
type Monitor struct {
	cfg     *config.WAFConfig
	xdp     XDPRuleManager
	banStore BanRecordStore // 封禁记录持久化（可选）
	ctx     context.Context
	cancel  context.CancelFunc
	watcher *fsnotify.Watcher
	filePos map[string]int64 // 按文件路径分别记录读取位置
	offsetStore *watcher.OffsetStore // 偏移量持久化存储
	wg       sync.WaitGroup // 等待 goroutine 退出

	// 已封禁 IP 缓存
	bannedIPs map[string]IPBanRecord
	mu       sync.RWMutex

	// 白名单检查函数（可选，由外部注入）
	whitelistCheck func(ip string) bool

	// 日志解析正则表达式
	// 常见的 WAF 日志格式：
	// 1. Caddy access log: "1.2.3.4 - - [date] \"GET /path\" status rule_id"
	// 2. Coraza WAF: "client_ip: 1.2.3.4, rule_id: 12345"
	// 3. Rate limit: "rate_limit_exceeded for 1.2.3.4"
	ipRegex *regexp.Regexp

	// Cron 定时任务
	cron *cron.Cron

	// 定时保存偏移量的 cancel 函数
	cancelPeriodicSave context.CancelFunc
}

// NewMonitor 创建 WAF 日志监控器
func NewMonitor(cfg *config.WAFConfig, xdp XDPRuleManager, ctx context.Context) *Monitor {
	childCtx, cancel := context.WithCancel(ctx)

	return &Monitor{
		cfg:       cfg,
		xdp:       xdp,
		ctx:       childCtx,
		cancel:    cancel,
		filePos:   make(map[string]int64),
		bannedIPs: make(map[string]IPBanRecord),
		// 匹配常见 IP 地址格式 (IPv4)
		ipRegex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	}
}

// SetBanRecordStore 设置封禁记录持久化存储
func (m *Monitor) SetBanRecordStore(store BanRecordStore) {
	m.banStore = store
}

// SetOffsetStore 设置偏移量持久化存储（可选）
func (m *Monitor) SetOffsetStore(store *watcher.OffsetStore) {
	m.offsetStore = store
}

// SetWhitelistCheck 设置白名单检查函数
// 在封禁 IP 前调用此函数判断 IP 是否在白名单中，避免白名单 IP 被写入黑名单
func (m *Monitor) SetWhitelistCheck(fn func(ip string) bool) {
	m.whitelistCheck = fn
}

// Start 启动 WAF 日志监控
func (m *Monitor) Start() error {
	// 加载持久化的偏移量
	if m.offsetStore != nil {
		m.offsetStore.Load()
	}

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

	// 初始化 Cron 定时任务
	m.cron = cron.New(cron.WithSeconds())

	// 添加定时清理任务（每 5 分钟）
	_, err = m.cron.AddFunc("@every 5m", func() {
		m.cleanup()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup cron job: %w", err)
	}

	// 启动定时任务
	m.cron.Start()

	// 启动监控 goroutine
	m.wg.Add(1)
	go m.monitorLoop()

	// 启动定时保存偏移量（每 5 秒）
	if m.offsetStore != nil {
		m.cancelPeriodicSave = m.offsetStore.StartPeriodicSave(5 * time.Second)
	}

	logger.Infof("[WAF] Monitor started, ban_duration=%d seconds", m.cfg.BanDuration)

	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	logger.Info("[WAF] Stopping monitor...")
	m.cancel()

	// 停止定时保存偏移量
	if m.cancelPeriodicSave != nil {
		m.cancelPeriodicSave()
	}

	// 停止 Cron 定时任务
	if m.cron != nil {
		m.cron.Stop()
	}

	if m.watcher != nil {
		m.watcher.Close()
	}

	// 等待所有 goroutine 退出，确保不会有并发的 SetOffset 调用
	m.wg.Wait()

	// goroutine 已退出，安全地最终保存偏移量
	if m.offsetStore != nil {
		m.offsetStore.Save()
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
	dirPath := filepath.Dir(filePath)
	if err := m.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", dirPath, err)
	}

	logger.Infof("[WAF] Watching log file: %s", filePath)
	return nil
}

// monitorLoop 监控循环
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()
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

	// 获取文件大小和 inode
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// 获取文件 inode（用于日志轮转检测）
	var currentInode uint64
	if stat, ok := fileInfo.Sys().(*syscallStatT); ok {
		currentInode = stat.Ino
	}

	// 检查是否发生日志轮转：inode 变化或文件变小
	fileSize := fileInfo.Size()
	pos := m.filePos[filePath]

	// 如果有持久化的偏移量，优先使用
	if m.offsetStore != nil {
		if savedOffset, savedInode, ok := m.offsetStore.GetOffset(filePath); ok {
			// inode 变化 → 日志轮转，从头读取
			if savedInode != 0 && savedInode != currentInode {
				logger.Infof("[WAF] Detected log rotation for %s (inode %d → %d), resetting offset", filePath, savedInode, currentInode)
				pos = 0
			} else if savedInode == currentInode && pos < savedOffset {
				// inode 一致则恢复偏移量
				pos = savedOffset
			}
		}
	}
	if fileSize < pos {
		pos = 0
	}

	// 从上次读取的位置开始读取
	if _, err := file.Seek(pos, 0); err != nil {
		return err
	}

	// 逐行读取新增内容
	scanner := bufio.NewScanner(file)
	lineCount := 0
	logSource := m.getLogSource(filePath)
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		if ip := m.extractIP(line, logSource); ip != "" {
			var mask uint32
			switch logSource {
			case "waf":
				mask = sourceMaskWAF
			case "rate_limit":
				mask = sourceMaskRateLimit
			default:
				mask = sourceMaskWAF
			}
			m.banIP(ip, filePath, mask)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// 更新读取位置
	m.filePos[filePath] = fileSize
	if m.offsetStore != nil {
		m.offsetStore.SetOffset(filePath, fileSize, currentInode)
	}

	if lineCount > 0 {
		logger.Debugf("[WAF] Processed %d new lines from %s", lineCount, filePath)
	}

	return nil
}

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

// extractIP 从日志行中提取 IP 地址
// logSource 标识日志来源（"waf" 或 "rate_limit"），用于选择不同的 IP 提取策略
func (m *Monitor) extractIP(line string, logSource string) string {
	switch logSource {
	case "rate_limit":
		// Rate limit 日志：优先使用 JSON 解析精确提取 remote_ip
		// 格式示例: {"level":"info","remote_ip":"1.2.3.4","msg":"rate limit exceeded"}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{") {
			var entry RateLimitLogEntry
			if err := json.Unmarshal([]byte(trimmed), &entry); err == nil && entry.RemoteIP != "" {
				return entry.RemoteIP
			}
		}
		// JSON 解析失败或非 JSON 格式，回退到正则匹配（向后兼容）
		matches := m.ipRegex.FindAllString(line, -1)
		if len(matches) == 0 {
			return ""
		}
		return matches[0]
	case "waf":
		// WAF 审计日志：解析 JSON 格式
		// 只有 is_interrupted==true 时才封禁 client_ip
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

		// 只有当 is_interrupted==true 时才封禁
		if !entry.Transaction.IsInterrupted {
			return ""
		}

		// 返回 client_ip
		return entry.Transaction.ClientIP
	default:
		// unknown 来源：使用正则提取第一个 IP（向后兼容）
		matches := m.ipRegex.FindAllString(line, -1)
		if len(matches) == 0 {
			return ""
		}
		return matches[0]
	}
}

// getLogSource 根据文件路径判断日志来源类型
// 使用 filepath.Clean 规范化路径后再比较，避免相对路径 vs 绝对路径导致匹配失败
func (m *Monitor) getLogSource(filePath string) string {
	cleanPath := filepath.Clean(filePath)
	if cleanPath == filepath.Clean(m.cfg.WAFLogPath) {
		return "waf"
	}
	if cleanPath == filepath.Clean(m.cfg.RateLimitLogPath) {
		return "rate_limit"
	}
	return "unknown"
}

// banIP 封禁 IP 地址（带去重和白名单检查）
func (m *Monitor) banIP(ip, logFile string, sourceMask uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 白名单检查：跳过白名单 IP，避免持续写入黑名单
	if m.whitelistCheck != nil && m.whitelistCheck(ip) {
		logger.Debugf("[WAF] IP %s is whitelisted, skipping ban", ip)
		return
	}

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
	if err := m.xdp.AddRuleWithSource(ip, sourceMask); err != nil {
		logger.Errorf("[WAF] Failed to add XDP rule for IP %s: %v", ip, err)
		return
	}

	// 记录封禁
	expiry := now.Add(time.Duration(m.cfg.BanDuration) * time.Second)
	m.bannedIPs[ip] = IPBanRecord{
		BannedAt:   now,
		Expiry:     expiry,
		SourceMask: sourceMask,
	}

	// 持久化封禁记录到数据库
	if m.banStore != nil {
		source := "waf"
		if sourceMask == sourceMaskRateLimit {
			source = "rate_limit"
		}
		reason := fmt.Sprintf("banned from %s log", m.getLogSource(logFile))
		if err := m.banStore.UpsertActiveBan(ip, source, reason, m.cfg.BanDuration); err != nil {
			logger.Errorf("[WAF] Failed to persist ban record for IP %s: %v", ip, err)
		}
	}

	logger.Infof("[WAF] Banned IP %s (from %s, expires at %v)", ip, logFile, expiry)
}

// cleanup 清理过期的封禁记录，并同步移除对应的 XDP 规则
// 采用两阶段策略：先在锁内收集过期 IP 并删除记录，再释放锁后执行 XDP 操作，
// 避免持锁期间因 XDP 调用阻塞 banIP()、IsBanned() 等其他操作。
func (m *Monitor) cleanup() {
	type expiredIP struct {
		ip     string
		record IPBanRecord
	}

	// 第一阶段：在锁内收集所有过期 IP 并从 bannedIPs 中删除
	var expired []expiredIP
	{
		m.mu.Lock()
		now := time.Now()
		for ip, record := range m.bannedIPs {
			if now.After(record.Expiry) {
				expired = append(expired, expiredIP{ip: ip, record: record})
				delete(m.bannedIPs, ip)
			}
		}
		m.mu.Unlock()
	}

	// 第二阶段：释放锁后，逐个调用 XDP 移除规则
	expiredCount := len(expired)
	for _, e := range expired {
		if _, _, _, err := m.xdp.UpdateRuleSourceMask(e.ip, e.record.SourceMask); err != nil {
			logger.Warnf("[WAF] Failed to remove XDP rule for expired IP %s: %v", e.ip, err)
		} else {
			logger.Debugf("[WAF] Removed XDP rule for expired IP %s", e.ip)
		}

		// 更新数据库中的封禁状态为已过期
		if m.banStore != nil {
			source := "waf"
			if e.record.SourceMask == sourceMaskRateLimit {
				source = "rate_limit"
			}
			if err := m.banStore.MarkExpired(e.ip, source); err != nil {
				logger.Warnf("[WAF] Failed to mark ban record expired for IP %s: %v", e.ip, err)
			}
		}
	}

	if expiredCount > 0 {
		logger.Infof("[WAF] Cleaned up %d expired IP bans and removed XDP rules", expiredCount)
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
