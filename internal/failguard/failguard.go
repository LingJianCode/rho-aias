package failguard

import (
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/internal/services"

	"github.com/robfig/cron/v3"
)

// Manager FailGuard eBPF 防爆破管理器（纯调度层）
type Manager struct {
	cfg     *config.FailGuardConfig
	monitor *EBPFMonitor
	cron    *cron.Cron
	running bool
}

// NewManager 创建 FailGuard 管理器
func NewManager(
	cfg *config.FailGuardConfig,
	xdpMgr EBPFManager,
	dbStore *services.BanRecordService,
	whitelistChecker *manual.WhitelistChecker,
) *Manager {
	return &Manager{
		cfg:     cfg,
		monitor: NewEBPFMonitor(cfg, xdpMgr, dbStore, NewBanFilter(whitelistChecker)),
	}
}

// Start 启动 eBPF 监控 + 定时清理任务
func (m *Manager) Start() error {
	if err := m.monitor.Start(); err != nil {
		return err
	}

	m.cron = cron.New(cron.WithSeconds())

	// 定期清理过期封禁记录（每 5 分钟，与 cleanupLoop 互为备份）
	_, err := m.cron.AddFunc("@every 5m", func() {
		if count := m.monitor.CleanupExpired(); count > 0 {
			logger.Debugf("[FailGuard] Cron cleaned up %d expired bans (full unban)", count)
		}
	})
	if err != nil {
		m.monitor.Stop()
		return err
	}

	m.cron.Start()
	m.running = true

	logger.Infof("[FailGuard] Monitor started (eBPF mode), ssh_ports=%v, max_retry=%d, find_time=%ds, ban_duration=%ds",
		m.cfg.SSHPorts, m.cfg.MaxRetry, m.cfg.FindTime, m.cfg.BanDuration)
	return nil
}

// Stop 停止监控
func (m *Manager) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.monitor.Stop()
	m.running = false
	logger.Info("[FailGuard] Monitor stopped")
}

// UpdateConfig 热更新配置
func (m *Manager) UpdateConfig(enabled bool, maxRetry, findTime, banDuration int, model string, ports []int, shortConnSeconds int) {
	m.cfg.Enabled = enabled
	m.cfg.MaxRetry = maxRetry
	m.cfg.FindTime = findTime
	m.cfg.BanDuration = banDuration

	// 更新 BanManager 参数
	m.monitor.banMgr.mu.Lock()
	m.monitor.banMgr.threshold = maxRetry
	m.monitor.banMgr.window = time.Duration(findTime) * time.Second
	m.monitor.banMgr.duration = time.Duration(banDuration) * time.Second
	m.monitor.banMgr.mu.Unlock()

	// 端口变更：通过 BPF_MAP_HASH Put 热更新
	if !intSliceEqual(m.cfg.SSHPorts, ports) {
		u16 := toUint16Slice(ports)
		logger.Infof("[FailGuard] Ports changed %v → %v, updating eBPF map", m.cfg.SSHPorts, ports)
		if err := m.monitor.UpdatePorts(u16); err != nil {
			logger.Errorf("[FailGuard] Failed to update monitored_ports at runtime: %v", err)
		}
		m.cfg.SSHPorts = ports
	}

	// 运行时配置变更（mode + shortConnSeconds）：通过 BPF_MAP_ARRAY Put 热更新
	modeChanged := m.cfg.Mode != model
	nsChanged := m.cfg.ShortConnSeconds != shortConnSeconds
	if modeChanged || nsChanged {
		logger.Infof("[FailGuard] Runtime config changed: mode=%s→%s, short_conn=%d→%ds",
			m.cfg.Mode, model, m.cfg.ShortConnSeconds, shortConnSeconds)
		if err := m.monitor.UpdateRuntimeConfig(shortConnSeconds, model); err != nil {
			logger.Errorf("[FailGuard] Failed to update config_map at runtime: %v", err)
		}
		m.cfg.Mode = model
		m.cfg.ShortConnSeconds = shortConnSeconds
	}

	logger.Infof("[FailGuard] Config updated: enabled=%v, ssh_ports=%v, short_conn=%ds, max_retry=%d, find_time=%d, ban_duration=%d, mode=%s",
		enabled, ports, shortConnSeconds, maxRetry, findTime, banDuration, m.cfg.Mode)
}

// GetConfig 获取当前可动态化字段
func (m *Manager) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":            m.cfg.Enabled,
		"ssh_ports":          m.cfg.SSHPorts,
		"short_conn_seconds": m.cfg.ShortConnSeconds,
		"max_retry":          m.cfg.MaxRetry,
		"find_time":          m.cfg.FindTime,
		"ban_duration":       m.cfg.BanDuration,
		"mode":               m.cfg.Mode,
	}
}

// GetBannedIPs 获取当前已封禁 IP 列表
func (m *Manager) GetBannedIPs() []string {
	return m.monitor.banMgr.GetBannedIPs()
}

// GetBanCount 获取当前封禁数量
func (m *Manager) GetBanCount() int {
	return m.monitor.banMgr.GetBanCount()
}

// IsBanned 检查 IP 是否被封禁
func (m *Manager) IsBanned(ip string) bool {
	return m.monitor.banMgr.IsBannedByString(ip)
}

// IsRunning 检查监控器是否正在运行
func (m *Manager) IsRunning() bool {
	return m.running
}

// intSliceEqual 比较两个 []int 是否相等
func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
