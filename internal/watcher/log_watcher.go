// Package watcher 提供日志文件监听的共享工具，包括读取偏移量的持久化存储和通用的日志监听+封禁管理
package watcher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"rho-aias/internal/logger"

	"github.com/fsnotify/fsnotify"
)

// XDPRuleManager 定义 XDP 规则操作接口（统一接口，供 waf/failguard 等模块复用）
type XDPRuleManager interface {
	AddRuleWithSource(ip string, sourceMask uint32) error
	UpdateRuleSourceMask(ip string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error)
}

// BanRecordStore 封禁记录持久化接口（统一接口，供 waf/failguard 等模块复用）
type BanRecordStore interface {
	UpsertActiveBan(ip, source, reason string, duration int) error
	MarkExpired(ip, source string) error
}

// IPBanRecord IP 封禁记录
type IPBanRecord struct {
	BannedAt   time.Time // 封禁时间
	Expiry     time.Time // 过期时间
	SourceMask uint32    // 封禁来源掩码，用于清理时使用正确的 mask
}

// LineHandler 日志行处理回调，由具体模块实现
// 返回 (ip, sourceMask, reason, banDuration, shouldBan)
// 如果 shouldBan 为 false，表示该行不应触发封禁
type LineHandler func(line string) (ip string, sourceMask uint32, reason string, banDuration int, shouldBan bool)

// LogWatcher 通用的日志文件监听+封禁管理组件
// 封装了文件监听、偏移量管理、增量读取、日志轮转检测、封禁去重/过期清理等通用逻辑
// 具体模块（WAF、FailGuard）通过注入 LineHandler 来定制日志解析逻辑
type LogWatcher struct {
	LogTag     string // 日志标签（如 "[WAF]"、"[FailGuard]"）
	BanSource  string // 封禁来源名称（如 "waf"、"failguard"），用于数据库记录

	xdp          XDPRuleManager
	banStore     BanRecordStore
	ctx          context.Context
	cancel       context.CancelFunc
	watcher      *fsnotify.Watcher
	filePos      map[string]int64
	offsetStore  *OffsetStore
	watchedFiles map[string]struct{} // 需要监听的目标文件路径列表

	// LineHandler 由外部模块注入，负责解析日志行并决定是否封禁
	lineHandler LineHandler

	// 已封禁 IP 缓存
	bannedIPs map[string]IPBanRecord
	mu        sync.RWMutex

	// 白名单检查函数（可选，由外部注入）
	whitelistCheck func(ip string) bool

	// 可观测的事件回调（可选，由外部模块注入用于额外处理）
	OnBan    func(ip string, record IPBanRecord)
	OnUnban  func(ip string, record IPBanRecord)
}

// NewLogWatcher 创建通用日志监听器
func NewLogWatcher(logTag, banSource string, xdp XDPRuleManager, ctx context.Context) *LogWatcher {
	childCtx, cancel := context.WithCancel(ctx)
	return &LogWatcher{
		LogTag:       logTag,
		BanSource:    banSource,
		xdp:          xdp,
		ctx:          childCtx,
		cancel:       cancel,
		filePos:      make(map[string]int64),
		watchedFiles: make(map[string]struct{}),
		bannedIPs:    make(map[string]IPBanRecord),
	}
}

// SetBanRecordStore 设置封禁记录持久化存储
func (w *LogWatcher) SetBanRecordStore(store BanRecordStore) {
	w.banStore = store
}

// SetOffsetStore 设置偏移量持久化存储（可选）
func (w *LogWatcher) SetOffsetStore(store *OffsetStore) {
	w.offsetStore = store
}

// SetWhitelistCheck 设置白名单检查函数
func (w *LogWatcher) SetWhitelistCheck(fn func(ip string) bool) {
	w.whitelistCheck = fn
}

// SetLineHandler 设置日志行处理回调
func (w *LogWatcher) SetLineHandler(handler LineHandler) {
	w.lineHandler = handler
}

// Context 返回内部 context（供外部模块添加定时任务等）
func (w *LogWatcher) Context() context.Context {
	return w.ctx
}

// WatchLogFile 监听单个日志文件所在目录
func (w *LogWatcher) WatchLogFile(filePath string) error {
	cleanPath := filepath.Clean(filePath)
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		logger.Warnf("[%s] Log file does not exist, will monitor for creation: %s", w.LogTag, cleanPath)
	}

	// 记录需要监听的目标文件
	w.watchedFiles[cleanPath] = struct{}{}

	dirPath := filepath.Dir(cleanPath)
	if err := w.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", dirPath, err)
	}

	logger.Infof("[%s] Watching log file: %s", w.LogTag, cleanPath)
	return nil
}

// Start 初始化 fsnotify 并启动监控 goroutine
func (w *LogWatcher) Start() error {
	// 加载持久化的偏移量
	if w.offsetStore != nil {
		w.offsetStore.Load()
	}

	// 初始化文件监听器
	fsnWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	w.watcher = fsnWatcher

	// 启动监控 goroutine
	go w.monitorLoop()

	// 启动定时保存偏移量（每 5 秒）
	if w.offsetStore != nil {
		w.offsetStore.StartPeriodicSave(5 * time.Second)
	}

	return nil
}

// Stop 停止监控
func (w *LogWatcher) Stop() {
	logger.Infof("[%s] Stopping log watcher...", w.LogTag)
	w.cancel()

	if w.watcher != nil {
		w.watcher.Close()
	}

	if w.offsetStore != nil {
		w.offsetStore.Save()
	}
	logger.Infof("[%s] Log watcher stopped", w.LogTag)
}

// isWatchedFile 检查文件路径是否是需要监听的目标文件
func (w *LogWatcher) isWatchedFile(filePath string) bool {
	cleanPath := filepath.Clean(filePath)
	_, ok := w.watchedFiles[cleanPath]
	return ok
}

// monitorLoop 监控循环
func (w *LogWatcher) monitorLoop() {
	for {
		select {
		case <-w.ctx.Done():
			logger.Infof("[%s] Monitor loop exit", w.LogTag)
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Create == fsnotify.Create {
				// 只处理目标文件
				if w.isWatchedFile(event.Name) {
					if err := w.ReadLogFile(event.Name); err != nil {
						logger.Errorf("[%s] Failed to read log file %s: %v", w.LogTag, event.Name, err)
					}
				}
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("[%s] Watcher error: %v", w.LogTag, err)
		}
	}
}

// ReadLogFile 读取日志文件的新内容（增量读取，处理日志轮转）
func (w *LogWatcher) ReadLogFile(filePath string) error {
	// 安全检查：只处理目标文件
	if !w.isWatchedFile(filePath) {
		return nil
	}

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

	fileSize := fileInfo.Size()
	pos := w.filePos[filePath]

	// 如果有持久化的偏移量，优先使用
	if w.offsetStore != nil {
		if savedOffset, savedInode, ok := w.offsetStore.GetOffset(filePath); ok {
			if savedInode != 0 && savedInode != currentInode {
				logger.Infof("[%s] Detected log rotation for %s (inode %d → %d), resetting offset", w.LogTag, filePath, savedInode, currentInode)
				pos = 0
			} else if savedInode == currentInode && pos < savedOffset {
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
		w.processLine(line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	w.filePos[filePath] = fileSize
	if w.offsetStore != nil {
		w.offsetStore.SetOffset(filePath, fileSize, currentInode)
	}

	if lineCount > 0 {
		logger.Debugf("[%s] Processed %d new lines from %s", w.LogTag, lineCount, filePath)
	}

	return nil
}

// processLine 处理一行日志：委托给 lineHandler，然后执行封禁
func (w *LogWatcher) processLine(line string) {
	if w.lineHandler == nil {
		return
	}

	ip, sourceMask, reason, banDuration, shouldBan := w.lineHandler(line)
	if !shouldBan || ip == "" {
		return
	}

	w.BanIP(ip, sourceMask, reason, banDuration)
}

// BanIP 封禁 IP 地址（带去重和白名单检查）
func (w *LogWatcher) BanIP(ip string, sourceMask uint32, reason string, banDuration int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 白名单检查
	if w.whitelistCheck != nil && w.whitelistCheck(ip) {
		logger.Debugf("[%s] IP %s is whitelisted, skipping ban", w.LogTag, ip)
		return
	}

	now := time.Now()

	// 去重：已封禁且未过期则跳过
	if record, exists := w.bannedIPs[ip]; exists {
		if now.Before(record.Expiry) {
			logger.Debugf("[%s] IP %s already banned (expires at %v), skipping", w.LogTag, ip, record.Expiry)
			return
		}
		logger.Infof("[%s] IP %s ban expired, re-banning", w.LogTag, ip)
	}

	// 调用 XDP 添加封禁规则
	if err := w.xdp.AddRuleWithSource(ip, sourceMask); err != nil {
		logger.Errorf("[%s] Failed to add XDP rule for IP %s: %v", w.LogTag, ip, err)
		return
	}

	// 记录封禁
	expiry := now.Add(time.Duration(banDuration) * time.Second)
	record := IPBanRecord{
		BannedAt:   now,
		Expiry:     expiry,
		SourceMask: sourceMask,
	}
	w.bannedIPs[ip] = record

	// 持久化到数据库
	if w.banStore != nil {
		if reason == "" {
			reason = fmt.Sprintf("banned by %s", w.BanSource)
		}
		if err := w.banStore.UpsertActiveBan(ip, w.BanSource, reason, banDuration); err != nil {
			logger.Errorf("[%s] Failed to persist ban record for IP %s: %v", w.LogTag, ip, err)
		}
	}

	// 回调通知
	if w.OnBan != nil {
		w.OnBan(ip, record)
	}

	logger.Infof("[%s] Banned IP %s for %ds (expires at %v)", w.LogTag, ip, banDuration, expiry)
}

// CleanupExpiredBans 清理过期的封禁记录，并同步移除对应的 XDP 规则
// 采用两阶段策略：先在锁内收集过期 IP 并删除记录，再释放锁后执行 XDP 操作
func (w *LogWatcher) CleanupExpiredBans() {
	type expiredIP struct {
		ip     string
		record IPBanRecord
	}

	var expired []expiredIP
	{
		w.mu.Lock()
		now := time.Now()
		for ip, record := range w.bannedIPs {
			if now.After(record.Expiry) {
				expired = append(expired, expiredIP{ip: ip, record: record})
				delete(w.bannedIPs, ip)
			}
		}
		w.mu.Unlock()
	}

	expiredCount := len(expired)
	for _, e := range expired {
		if _, _, _, err := w.xdp.UpdateRuleSourceMask(e.ip, e.record.SourceMask); err != nil {
			logger.Warnf("[%s] Failed to remove XDP rule for expired IP %s: %v", w.LogTag, e.ip, err)
		} else {
			logger.Debugf("[%s] Removed XDP rule for expired IP %s", w.LogTag, e.ip)
		}

		if w.banStore != nil {
			if err := w.banStore.MarkExpired(e.ip, w.BanSource); err != nil {
				logger.Warnf("[%s] Failed to mark ban record expired for IP %s: %v", w.LogTag, e.ip, err)
			}
		}

		if w.OnUnban != nil {
			w.OnUnban(e.ip, e.record)
		}
	}

	if expiredCount > 0 {
		logger.Infof("[%s] Cleaned up %d expired IP bans", w.LogTag, expiredCount)
	}
}

// IsBanned 检查 IP 是否被封禁
func (w *LogWatcher) IsBanned(ip string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	record, exists := w.bannedIPs[ip]
	if !exists {
		return false
	}
	return time.Now().Before(record.Expiry)
}

// GetBannedIPs 获取当前已封禁的 IP 列表
func (w *LogWatcher) GetBannedIPs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	now := time.Now()
	ips := make([]string, 0, len(w.bannedIPs))
	for ip, record := range w.bannedIPs {
		if now.Before(record.Expiry) {
			ips = append(ips, ip)
		}
	}
	return ips
}

// GetBanCount 获取当前封禁的 IP 数量
func (w *LogWatcher) GetBanCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range w.bannedIPs {
		if now.Before(record.Expiry) {
			count++
		}
	}
	return count
}

// --- 以下方法仅供内部包测试使用 ---

// GetFilePos 获取文件偏移量 map（测试用）
func (w *LogWatcher) GetFilePos() map[string]int64 {
	return w.filePos
}

// GetBanRecord 获取指定 IP 的封禁记录（测试用）
func (w *LogWatcher) GetBanRecord(ip string) (IPBanRecord, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	record, exists := w.bannedIPs[ip]
	return record, exists
}

// SetBanRecordForTest 直接设置封禁记录（测试用）
func (w *LogWatcher) SetBanRecordForTest(ip string, record IPBanRecord) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bannedIPs[ip] = record
}

// SetFilePosForTest 直接设置文件读取位置（测试用）
func (w *LogWatcher) SetFilePosForTest(filePath string, pos int64) {
	w.filePos[filePath] = pos
}
