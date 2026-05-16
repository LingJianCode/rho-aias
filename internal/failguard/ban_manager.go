package failguard

import (
	"net"
	"sync"
	"time"
)

// BanManager 滑动窗口封禁管理器
// 线程安全：所有公开方法均带锁
type BanManager struct {
	mu        sync.Mutex
	threshold int          // 触发封禁的失败次数阈值
	window    time.Duration // 滑动窗口时长
	duration  time.Duration // 封禁时长（0 = 永久）

	// attempts: IP(网络字节序uint32) → 失败时间戳列表
	attempts map[uint32][]time.Time
	// banned: IP → 封禁过期时间（零值表示永久封禁）
	banned map[uint32]time.Time
}

// NewBanManager 创建滑动窗口封禁管理器
func NewBanManager(threshold, findTime, banDuration int, _ interface{}) *BanManager {
	return &BanManager{
		threshold: threshold,
		window:    time.Duration(findTime) * time.Second,
		duration:  time.Duration(banDuration) * time.Second,
		attempts:  make(map[uint32][]time.Time),
		banned:    make(map[uint32]time.Time),
	}
}

// RegisterFailure 注册一次失败，返回是否达到阈值需要封禁及过期时间
// 如果已封禁则返回 (false, 过期时间)
func (m *BanManager) RegisterFailure(ip uint32) (shouldBan bool, expiresAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 已封禁 → 跳过
	if exp, banned := m.banned[ip]; banned {
		if exp.IsZero() || now.Before(exp) {
			return false, exp
		}
		// 已过期，清除旧记录重新计数
		delete(m.banned, ip)
	}

	cutoff := now.Add(-m.window)
	var valid []time.Time
	for _, ts := range m.attempts[ip] {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	m.attempts[ip] = valid

	if len(valid) < m.threshold {
		return false, time.Time{}
	}

	// 达到阈值 → 封禁
	if m.duration > 0 {
		expiresAt = now.Add(m.duration)
	}
	m.banned[ip] = expiresAt
	delete(m.attempts, ip)

	return true, expiresAt
}

// ForceBan 强制封禁指定 IP（用于 preauth 异常等直接触发场景）
func (m *BanManager) ForceBan(ip uint32) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var expiresAt time.Time
	if m.duration > 0 {
		expiresAt = now.Add(m.duration)
	}
	m.banned[ip] = expiresAt
	delete(m.attempts, ip)
	return expiresAt
}

// Expired 清理已过期的封禁记录，返回被清理的 IP 列表（字符串格式）
func (m *BanManager) Expired() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.duration <= 0 {
		return nil
	}

	now := time.Now()
	var expired []string
	for ip, expiresAt := range m.banned {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			expiredStr := FormatRemoteIP(ip)
			expired = append(expired, expiredStr)
			delete(m.banned, ip)
		}
	}
	return expired
}

// IsBanned 检查 IP 是否当前被封禁
func (m *BanManager) IsBanned(rawIP uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if exp, exists := m.banned[rawIP]; exists {
		if exp.IsZero() {
			return true // 永久封禁
		}
		return time.Now().Before(exp)
	}
	return false
}

// IsBannedByString 通过字符串 IP 检查是否被封禁
func (m *BanManager) IsBannedByString(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return false
	}
	rawIP := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	return m.IsBanned(rawIP)
}

// GetBanCount 返回当前封禁数量
func (m *BanManager) GetBanCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.banned)
}

// GetBannedIPs 返回当前被封禁的 IP 字符串列表
func (m *BanManager) GetBannedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var ips []string
	for ip, exp := range m.banned {
		if !exp.IsZero() && !now.Before(exp) {
			continue // 过期的不返回
		}
		ips = append(ips, FormatRemoteIP(ip))
	}
	return ips
}
