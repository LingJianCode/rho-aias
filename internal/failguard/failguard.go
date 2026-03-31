package failguard

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/watcher"

	"github.com/fsnotify/fsnotify"
	"github.com/robfig/cron/v3"
)

// sourceMaskFailGuard FailGuard 来源掩码，与 ebpfs.SourceMaskFailGuard (0x80) 保持一致
const sourceMaskFailGuard uint32 = 0x80

// XDPRuleManager 定义 FailGuard 所需的 XDP 规则操作接口
type XDPRuleManager interface {
	AddRuleWithSource(ip string, sourceMask uint32) error
	UpdateRuleSourceMask(ip string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error)
}

// BanRecordStore 封禁记录持久化接口
type BanRecordStore interface {
	UpsertActiveBan(ip, source, reason string, duration int) error
	MarkExpired(ip, source string) error
}

// IPBanRecord IP 封禁记录
type IPBanRecord struct {
	BannedAt   time.Time
	Expiry     time.Time
	SourceMask uint32
}

// Monitor FailGuard 日志监控器
type Monitor struct {
	cfg     *config.FailGuardConfig
	xdp     XDPRuleManager
	banStore BanRecordStore
	ctx     context.Context
	cancel  context.CancelFunc
	watcher *fsnotify.Watcher
	filePos map[string]int64
	offsetStore *watcher.OffsetStore // 偏移量持久化存储

	// 编译后的正则
	failRegex   []*regexp.Regexp
	ignoreRegex []*regexp.Regexp
	ignoreCIDRs []*net.IPNet

	// 白名单检查函数（可选，由外部注入）
	whitelistCheck func(ip string) bool

	// 失败计数器：IP → 失败时间戳列表（滑动窗口）
	failures map[string][]time.Time
	failMu   sync.Mutex

	// 封禁记录
	bannedIPs map[string]IPBanRecord
	banMu     sync.RWMutex

	// Cron 定时任务
	cron *cron.Cron
}

// NewMonitor 创建 FailGuard 日志监控器
func NewMonitor(cfg *config.FailGuardConfig, xdp XDPRuleManager, ctx context.Context) *Monitor {
	childCtx, cancel := context.WithCancel(ctx)

	m := &Monitor{
		cfg:       cfg,
		xdp:       xdp,
		ctx:       childCtx,
		cancel:    cancel,
		filePos:   make(map[string]int64),
		failures:  make(map[string][]time.Time),
		bannedIPs: make(map[string]IPBanRecord),
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
			// 尝试作为纯 IP 解析
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

	return m
}

// SetOffsetStore 设置偏移量持久化存储（可选）
func (m *Monitor) SetOffsetStore(store *watcher.OffsetStore) {
	m.offsetStore = store
}

// SetBanRecordStore 设置封禁记录持久化存储
func (m *Monitor) SetBanRecordStore(store BanRecordStore) {
	m.banStore = store
}

// SetWhitelistCheck 设置白名单检查函数
// 在封禁 IP 前调用此函数判断 IP 是否在白名单中，避免白名单 IP 被写入黑名单
func (m *Monitor) SetWhitelistCheck(fn func(ip string) bool) {
	m.whitelistCheck = fn
}

// Start 启动 FailGuard 日志监控
func (m *Monitor) Start() error {
	if m.cfg.LogPath == "" {
		return fmt.Errorf("log_path is required")
	}

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

	// 监听日志文件
	if err := m.watchLogFile(m.cfg.LogPath); err != nil {
		return fmt.Errorf("failed to watch log file: %w", err)
	}

	// 初始化 Cron 定时任务
	m.cron = cron.New(cron.WithSeconds())

	// 添加定时清理封禁任务（每 5 分钟）
	_, err = m.cron.AddFunc("@every 5m", func() {
		m.cleanupBans()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup bans cron job: %w", err)
	}

	// 添加定时清理失败计数任务（每 1 分钟）
	_, err = m.cron.AddFunc("@every 1m", func() {
		m.cleanupFailures()
	})
	if err != nil {
		return fmt.Errorf("failed to add cleanup failures cron job: %w", err)
	}

	// 启动定时任务
	m.cron.Start()

	// 启动监控 goroutine
	go m.monitorLoop()

	logger.Infof("[FailGuard] Monitor started, mode=%s, log=%s, max_retry=%d, find_time=%ds, ban_duration=%ds",
		m.cfg.Mode, m.cfg.LogPath, m.cfg.MaxRetry, m.cfg.FindTime, m.cfg.BanDuration)

	return nil
}

// Stop 停止监控
func (m *Monitor) Stop() {
	logger.Info("[FailGuard] Stopping monitor...")
	m.cancel()

	// 停止 Cron 定时任务
	if m.cron != nil {
		m.cron.Stop()
	}

	if m.watcher != nil {
		m.watcher.Close()
	}
	// 保存偏移量
	if m.offsetStore != nil {
		m.offsetStore.Save()
	}
	logger.Info("[FailGuard] Monitor stopped")
}

// watchLogFile 监听单个日志文件
func (m *Monitor) watchLogFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logger.Warnf("[FailGuard] Log file does not exist, will monitor for creation: %s", filePath)
	}

	dirPath := filepath.Dir(filePath)
	if err := m.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", dirPath, err)
	}

	logger.Infof("[FailGuard] Watching log file: %s", filePath)
	return nil
}

// monitorLoop 监控循环
func (m *Monitor) monitorLoop() {
	for {
		select {
		case <-m.ctx.Done():
			logger.Info("[FailGuard] Monitor loop exit")
			return

		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Create == fsnotify.Create {
				m.handleLogFileEvent(event.Name)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("[FailGuard] Watcher error: %v", err)
		}
	}
}

// handleLogFileEvent 处理日志文件事件
func (m *Monitor) handleLogFileEvent(filePath string) {
	cleanPath := filepath.Clean(filePath)
	if cleanPath != filepath.Clean(m.cfg.LogPath) {
		return
	}

	if err := m.readLogFile(filePath); err != nil {
		logger.Errorf("[FailGuard] Failed to read log file %s: %v", filePath, err)
	}
}

// readLogFile 读取日志文件的新内容（增量读取，处理日志轮转）
func (m *Monitor) readLogFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// 获取文件 inode（用于日志轮转检测）
	var currentInode uint64
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
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
				logger.Infof("[FailGuard] Detected log rotation for %s (inode %d → %d), resetting offset", filePath, savedInode, currentInode)
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

	if _, err := file.Seek(pos, 0); err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		m.processLine(line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	m.filePos[filePath] = fileSize
	if m.offsetStore != nil {
		m.offsetStore.SetOffset(filePath, fileSize, currentInode)
	}

	if lineCount > 0 {
		logger.Debugf("[FailGuard] Processed %d new lines from %s", lineCount, filePath)
	}

	return nil
}

// processLine 处理一行日志
func (m *Monitor) processLine(line string) {
	// 1. ignoreregex 匹配 → 跳过
	if m.matchIgnore(line) {
		return
	}

	// 2. failregex 匹配 → 提取 IP
	ip := m.matchFail(line)
	if ip == "" {
		return
	}

	// 3. 白名单跳过
	if m.isIgnoredIP(ip) {
		return
	}

	// 4. 已封禁跳过
	if m.isBanned(ip) {
		return
	}

	// 5. 滑动窗口计数，达阈值则封禁
	if m.addFailureAndCheck(ip) {
		m.banIP(ip)
		// 封禁成功后清零计数器（在 banIP 外部操作 failMu，避免嵌套锁）
		m.failMu.Lock()
		delete(m.failures, ip)
		m.failMu.Unlock()
	}
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

// banIP 封禁 IP
func (m *Monitor) banIP(ip string) {
	m.banMu.Lock()
	defer m.banMu.Unlock()

	now := time.Now()

	// 白名单检查：跳过白名单 IP，避免持续写入黑名单
	if m.whitelistCheck != nil && m.whitelistCheck(ip) {
		logger.Debugf("[FailGuard] IP %s is whitelisted, skipping ban", ip)
		return
	}

	// 去重：已封禁则跳过
	if record, exists := m.bannedIPs[ip]; exists {
		if now.Before(record.Expiry) {
			logger.Debugf("[FailGuard] IP %s already banned (expires at %v), skipping", ip, record.Expiry)
			return
		}
		logger.Infof("[FailGuard] IP %s ban expired, re-banning", ip)
	}

	// XDP 封禁
	if err := m.xdp.AddRuleWithSource(ip, sourceMaskFailGuard); err != nil {
		logger.Errorf("[FailGuard] Failed to add XDP rule for IP %s: %v", ip, err)
		return
	}

	// 记录封禁
	expiry := now.Add(time.Duration(m.cfg.BanDuration) * time.Second)
	m.bannedIPs[ip] = IPBanRecord{
		BannedAt:   now,
		Expiry:     expiry,
		SourceMask: sourceMaskFailGuard,
	}

	// 持久化到数据库
	if m.banStore != nil {
		if err := m.banStore.UpsertActiveBan(ip, "failguard", "SSH brute force", m.cfg.BanDuration); err != nil {
			logger.Errorf("[FailGuard] Failed to persist ban record for IP %s: %v", ip, err)
		}
	}

	logger.Infof("[FailGuard] Banned IP %s for %ds (SSH brute force, expires at %v)", ip, m.cfg.BanDuration, expiry)
}

// isBanned 检查 IP 是否已封禁
func (m *Monitor) isBanned(ip string) bool {
	m.banMu.RLock()
	defer m.banMu.RUnlock()

	record, exists := m.bannedIPs[ip]
	if !exists {
		return false
	}
	return time.Now().Before(record.Expiry)
}

// cleanupBans 清理过期的封禁记录
func (m *Monitor) cleanupBans() {
	type expiredIP struct {
		ip     string
		record IPBanRecord
	}

	var expired []expiredIP
	{
		m.banMu.Lock()
		now := time.Now()
		for ip, record := range m.bannedIPs {
			if now.After(record.Expiry) {
				expired = append(expired, expiredIP{ip: ip, record: record})
				delete(m.bannedIPs, ip)
			}
		}
		m.banMu.Unlock()
	}

	for _, e := range expired {
		if _, _, _, err := m.xdp.UpdateRuleSourceMask(e.ip, e.record.SourceMask); err != nil {
			logger.Warnf("[FailGuard] Failed to remove XDP rule for expired IP %s: %v", e.ip, err)
		}

		if m.banStore != nil {
			if err := m.banStore.MarkExpired(e.ip, "failguard"); err != nil {
				logger.Warnf("[FailGuard] Failed to mark ban record expired for IP %s: %v", e.ip, err)
			}
		}
	}

	if len(expired) > 0 {
		logger.Infof("[FailGuard] Cleaned up %d expired IP bans", len(expired))
	}
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

// GetBannedIPs 获取当前已封禁的 IP 列表
func (m *Monitor) GetBannedIPs() []string {
	m.banMu.RLock()
	defer m.banMu.RUnlock()

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
	m.banMu.RLock()
	defer m.banMu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range m.bannedIPs {
		if now.Before(record.Expiry) {
			count++
		}
	}
	return count
}
