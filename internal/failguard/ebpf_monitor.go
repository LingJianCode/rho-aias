package failguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"

	"github.com/cilium/ebpf/ringbuf"
)

// EBPFMonitor eBPF 监控引擎
// 负责加载 eBPF 程序、附加 probe、读取 RingBuf 事件、执行封禁
type EBPFMonitor struct {
	cfg    *config.FailGuardConfig
	xdpMgr EBPFManager
	banMgr *BanManager
	filter *BanFilter

	// eBPF 运行时资源（通过 SshMonitor 门面管理）
	monitor *ebpfs.SshMonitor
	reader  *ringbuf.Reader
	done    chan struct{}
	mu      sync.Mutex
	running bool

	// 统计计数器（仅用于日志/监控展示）
	statsMu     sync.RWMutex
	totalEvents int64
	totalBans   int64
}

// NewEBPFMonitor 创建 eBPF 监控实例
func NewEBPFMonitor(
	cfg *config.FailGuardConfig,
	xdpMgr EBPFManager,
	store interface{}, // 可选：*services.BanRecordService（用于持久化），或 nil
	filter *BanFilter,
) *EBPFMonitor {
	return &EBPFMonitor{
		cfg:     cfg,
		xdpMgr:  xdpMgr,
		banMgr:  NewBanManager(cfg.MaxRetry, cfg.FindTime, cfg.BanDuration, nil),
		filter:  filter,
		monitor: ebpfs.NewSshMonitor(),
		done:    make(chan struct{}),
	}
}

// Start 加载并启动 eBPF 监控
func (m *EBPFMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("eBPF monitor already running")
	}

	// 1. 加载 eBPF 对象（含全局变量配置）
	if err := m.monitor.Load(uint16(m.cfg.SSHPort), m.cfg.ShortConnSeconds); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	// 2. 附加 probes
	if err := m.monitor.AttachProbes(); err != nil {
		m.closeResources()
		return fmt.Errorf("attach probes: %w", err)
	}

	// 4. 启动 RingBuf 读取循环
	var err error
	m.reader, err = m.monitor.EventsReader()
	if err != nil {
		m.closeResources()
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	m.running = true
	go m.eventLoop()
	go m.cleanupLoop()

	logger.Infof("[FailGuard] eBPF monitor started, ssh_port=%d, max_retry=%d, find_time=%ds, ban_duration=%ds",
		m.cfg.SSHPort, m.cfg.MaxRetry, m.cfg.FindTime, m.cfg.BanDuration)
	return nil
}

// Stop 停止监控并释放所有资源
func (m *EBPFMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}
	m.running = false

	close(m.done)
	m.done = make(chan struct{}) // 重置以便可能的 restart

	m.closeResources()
	logger.Info("[FailGuard] eBPF monitor stopped")
}

// IsRunning 检查是否正在运行
func (m *EBPFMonitor) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// GetStats 获取统计信息
func (m *EBPFMonitor) GetStats() (events, bans int64) {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()
	return m.totalEvents, m.totalBans
}

// ============================================
// 内部方法：加载与配置
// ============================================

// ============================================
// 内部方法：Probe 附加（已委托给 SshMonitor）
// ============================================

// ============================================
// 内部方法：事件循环
// ============================================

func (m *EBPFMonitor) eventLoop() {
	logger.Info("[FailGuard] Event loop started")
	for {
		select {
		case <-m.done:
			logger.Info("[FailGuard] Event loop exit")
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Warn("[FailGuard] Ringbuf closed, stopping event loop")
				return
			}
			select {
			case <-m.done:
				return
			default:
				continue
			}
		}

		var event SSHEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Warnf("[FailGuard] Failed to parse event: %v", err)
			continue
		}

		m.statsMu.Lock()
		m.totalEvents++
		m.statsMu.Unlock()

		switch event.Type {
		case EventAuthResult:
			m.handleAuthResult(event)
		case EventPreauthShortConn:
			m.handlePreauthShortConn(event)
		default:
			logger.Debugf("[FailGuard] Unknown event type: %d", event.Type)
		}
	}
}

// handleAuthResult 处理 PAM 认证结果事件
// ret_code == 0 表示认证成功，非零表示失败
func (m *EBPFMonitor) handleAuthResult(e SSHEvent) {
	if e.RemoteIP == 0 || e.PID == 0 {
		return
	}

	ipStr := FormatRemoteIP(e.RemoteIP)

	// 认证成功 → 不处理
	if e.RetCode == 0 {
		logger.Debugf("[FailGuard] Auth success pid=%d from %s", e.PID, ipStr)
		return
	}

	// 白名单检查
	if !m.filter.ShouldBlock(ipStr) {
		logger.Debugf("[FailGuard] Auth failure whitelisted: %s", ipStr)
		return
	}

	// 注册失败，检查是否达到阈值
	shouldBan, expiresAt := m.banMgr.RegisterFailure(e.RemoteIP)
	if !shouldBan {
		logger.Debugf("[FailGuard] Auth failure count++ for %s (not yet banned)", ipStr)
		return
	}

	// 执行封禁
	m.executeBan(ipStr, expiresAt, "SSH auth failure")
}

// handlePreauthShortConn 处理 preauth 阶段异常短连接
func (m *EBPFMonitor) handlePreauthShortConn(e SSHEvent) {
	if e.RemoteIP == 0 || e.PID == 0 {
		return
	}

	ipStr := FormatRemoteIP(e.RemoteIP)

	// 白名单检查
	if !m.filter.ShouldBlock(ipStr) {
		return
	}

	// preauth 异常直接强制封禁（不经过滑动窗口计数）
	expiresAt := m.banMgr.ForceBan(e.RemoteIP)
	m.executeBan(ipStr, expiresAt, "SSH preauth anomaly")
}

// executeBan 通过 XDP 执行封禁
func (m *EBPFMonitor) executeBan(ip string, expiresAt time.Time, reason string) {
	err := m.xdpMgr.AddRuleWithSourceAndExpiry(ip, ebpfs.SourceMaskFailGuard, m.cfg.BanDuration)
	if err != nil {
		logger.Errorf("[FailGuard] Failed to ban %s via XDP: %v (reason: %s)", ip, err, reason)
		return
	}

	m.statsMu.Lock()
	m.totalBans++
	m.statsMu.Unlock()

	expiryStr := "permanent"
	if !expiresAt.IsZero() {
		expiryStr = expiresAt.Format("2006-01-02 15:04:05")
	}
	logger.Warnf("[FailGuard] BANNED %s until %s [reason: %s]", ip, expiryStr, reason)
}

// cleanupLoop 定期清理过期封禁记录
func (m *EBPFMonitor) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			expired := m.banMgr.Expired()
			if len(expired) > 0 {
				logger.Debugf("[FailGuard] Cleaned up %d expired ban records", len(expired))
			}
		}
	}
}

// closeResources 关闭所有资源（不加锁，由 Stop 调用）
func (m *EBPFMonitor) closeResources() {
	if m.reader != nil {
		m.reader.Close()
		m.reader = nil
	}
	if m.monitor != nil {
		m.monitor.Close()
	}
}


