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

	logger.Infof("[FailGuard] Monitor started (eBPF mode), ssh_port=%d, max_retry=%d, find_time=%ds, ban_duration=%ds",
		m.cfg.SSHPort, m.cfg.MaxRetry, m.cfg.FindTime, m.cfg.BanDuration)
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
func (m *Manager) UpdateConfig(enabled bool, maxRetry, findTime, banDuration int, model string) {
	m.cfg.Enabled = enabled
	m.cfg.MaxRetry = maxRetry
	m.cfg.FindTime = findTime
	m.cfg.BanDuration = banDuration
	m.cfg.Mode = model

	// 更新 BanManager 参数
	m.monitor.banMgr.mu.Lock()
	m.monitor.banMgr.threshold = maxRetry
	m.monitor.banMgr.window = time.Duration(findTime) * time.Second
	m.monitor.banMgr.duration = time.Duration(banDuration) * time.Second
	m.monitor.banMgr.mu.Unlock()

	logger.Infof("[FailGuard] Config updated: enabled=%v, max_retry=%d, find_time=%d, ban_duration=%d",
		enabled, maxRetry, findTime, banDuration)
}

// GetConfig 获取当前可动态化字段
func (m *Manager) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      m.cfg.Enabled,
		"max_retry":    m.cfg.MaxRetry,
		"find_time":    m.cfg.FindTime,
		"ban_duration": m.cfg.BanDuration,
		"mode":         m.cfg.Mode,
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
