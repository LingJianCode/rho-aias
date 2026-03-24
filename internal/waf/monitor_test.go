package waf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rho-aias/internal/config"
)

// mockXDPRuleManager 是 XDPRuleManager 接口的 mock 实现，用于单元测试
type mockXDPRuleManager struct {
	mu              sync.Mutex
	addedIPs        map[string]uint32   // 记录通过 AddRuleWithSource 添加的 IP 及其 sourceMask
	removedSources  map[string]uint32   // 记录通过 UpdateRuleSourceMask 移除的来源
	addErr          error               // AddRuleWithSource 返回的错误
	removeErr       error               // UpdateRuleSourceMask 返回的错误
	addCallCount    int                 // AddRuleWithSource 调用次数
	removeCallCount int                 // UpdateRuleSourceMask 调用次数
}

func newMockXDPRuleManager() *mockXDPRuleManager {
	return &mockXDPRuleManager{
		addedIPs:       make(map[string]uint32),
		removedSources: make(map[string]uint32),
	}
}

func (m *mockXDPRuleManager) AddRuleWithSource(ip string, sourceMask uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addCallCount++
	if m.addErr != nil {
		return m.addErr
	}
	m.addedIPs[ip] = sourceMask
	return nil
}

func (m *mockXDPRuleManager) UpdateRuleSourceMask(ip string, removeMask uint32) (uint32, bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeCallCount++
	if m.removeErr != nil {
		return 0, false, false, m.removeErr
	}
	m.removedSources[ip] = removeMask
	// 模拟：返回新掩码为 0（规则被删除）
	return 0, true, true, nil
}

func (m *mockXDPRuleManager) getAddedIPs() map[string]uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]uint32)
	for k, v := range m.addedIPs {
		result[k] = v
	}
	return result
}

func (m *mockXDPRuleManager) getRemovedSources() map[string]uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]uint32)
	for k, v := range m.removedSources {
		result[k] = v
	}
	return result
}

// testConfig 返回测试用的 WAF 配置
func testConfig(banDuration int) *config.WAFConfig {
	return &config.WAFConfig{
		Enabled:          true,
		WAFLogPath:       "/logs/waf_audit.log",
		RateLimitLogPath: "/logs/rate_limit.log",
		BanDuration:      banDuration,
	}
}

// ============================================
// NewMonitor 测试
// ============================================

func TestNewMonitor(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()

	monitor := NewMonitor(cfg, mockXDP, ctx)

	if monitor == nil {
		t.Fatal("NewMonitor() returned nil")
	}

	// 验证字段初始化
	if monitor.cfg != cfg {
		t.Error("cfg not set correctly")
	}
	if monitor.filePos == nil {
		t.Error("filePos should be initialized as non-nil map")
	}
	if monitor.bannedIPs == nil {
		t.Error("bannedIPs should be initialized as non-nil map")
	}
	if monitor.ipRegex == nil {
		t.Error("ipRegex should be initialized")
	}
	if len(monitor.filePos) != 0 {
		t.Errorf("filePos should be empty, got %d entries", len(monitor.filePos))
	}
	if len(monitor.bannedIPs) != 0 {
		t.Errorf("bannedIPs should be empty, got %d entries", len(monitor.bannedIPs))
	}
}

func TestNewMonitor_CreatesChildContext(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	monitor := NewMonitor(cfg, mockXDP, parentCtx)

	// 验证子 context 是独立的
	if monitor.ctx == nil {
		t.Fatal("child context should not be nil")
	}

	// 取消子 context 不影响父 context
	monitor.cancel()
	select {
	case <-monitor.ctx.Done():
		// 子 context 已取消
	default:
		t.Fatal("child context should be done after cancel")
	}

	// 父 context 不应被取消
	select {
	case <-parentCtx.Done():
		t.Fatal("parent context should not be done")
	default:
		// 父 context 仍然活跃
	}
}

// ============================================
// extractIP 测试
// ============================================

func TestExtractIP_NoMatch(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name      string
		line      string
		logSource string
		want      string
	}{
		{
			name:      "empty line",
			line:      "",
			logSource: "waf",
			want:      "",
		},
		{
			name:      "no IP in line",
			line:      "this line has no ip address",
			logSource: "waf",
			want:      "",
		},
		{
			name:      "invalid IP format",
			line:      "ip: 999.999.999.999",
			logSource: "rate_limit",
			want:      "",
		},
		{
			name:      "partial IP",
			line:      "ip: 192.168.1",
			logSource: "waf",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line, tt.logSource)
			if got != tt.want {
				t.Errorf("extractIP(%q, %q) = %q, want %q", tt.line, tt.logSource, got, tt.want)
			}
		})
	}
}

func TestExtractIP_RateLimitSource(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name      string
		line      string
		logSource string
		want      string
	}{
		{
			name:      "single IP in rate limit log",
			line:      "rate_limit_exceeded for 1.2.3.4",
			logSource: "rate_limit",
			want:      "1.2.3.4",
		},
		{
			name:      "rate limit log with timestamp",
			line:      "2024-01-15T10:30:00Z rate_limit_exceeded for 10.20.30.40",
			logSource: "rate_limit",
			want:      "10.20.30.40",
		},
		{
			name:      "rate limit log with multiple IPs - first is client",
			line:      "rate_limit: 192.168.1.100 exceeded for 1.2.3.4",
			logSource: "rate_limit",
			want:      "192.168.1.100",
		},
		{
			name:      "Caddy access log format",
			line:      "1.2.3.4 - - [15/Jan/2024:10:30:00 +0000] \"GET /api HTTP/1.1\" 200",
			logSource: "rate_limit",
			want:      "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line, tt.logSource)
			if got != tt.want {
				t.Errorf("extractIP(%q, %q) = %q, want %q", tt.line, tt.logSource, got, tt.want)
			}
		})
	}
}

func TestExtractIP_WAFSource(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name      string
		line      string
		logSource string
		want      string
	}{
		{
			name:      "WAF log with server and client IP - should take last (client)",
			line:      "server: 10.0.0.1 -> client: 1.2.3.4, rule_id: 12345",
			logSource: "waf",
			want:      "1.2.3.4",
		},
		{
			name:      "WAF log with single IP",
			line:      "client_ip: 192.168.1.100, rule_id: 942100",
			logSource: "waf",
			want:      "192.168.1.100",
		},
		{
			name:      "WAF log with multiple server IPs and client IP",
			line:      "proxy1: 10.0.0.1 proxy2: 10.0.0.2 -> client: 203.0.113.50 matched rule 941100",
			logSource: "waf",
			want:      "203.0.113.50",
		},
		{
			name:      "Coraza WAF audit log format",
			line:      "client_ip: 172.16.0.5, rule_id: 942100, msg: SQL Injection",
			logSource: "waf",
			want:      "172.16.0.5",
		},
		{
			name:      "WAF log with X-Forwarded-For",
			line:      "xff: 8.8.8.8, server: 10.0.0.1, client: 192.168.100.50, rule: 941160",
			logSource: "waf",
			want:      "192.168.100.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line, tt.logSource)
			if got != tt.want {
				t.Errorf("extractIP(%q, %q) = %q, want %q", tt.line, tt.logSource, got, tt.want)
			}
		})
	}
}

func TestExtractIP_UnknownSource(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	// unknown 来源应默认取第一个 IP
	line := "10.0.0.1 1.2.3.4 5.6.7.8"
	got := monitor.extractIP(line, "unknown")
	if got != "10.0.0.1" {
		t.Errorf("extractIP with unknown source should return first IP, got %q", got)
	}
}

func TestExtractIP_IPv4BoundaryValues(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name string
		line string
		want string
	}{
		{"min IP", "0.0.0.1", "0.0.0.1"},
		{"max IP", "255.255.255.255", "255.255.255.255"},
		{"IP with leading zeros", "001.002.003.004", "001.002.003.004"},
		{"IP in URL context", "http://192.168.1.1:8080/path", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line, "rate_limit")
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// ============================================
// getLogSource 测试
// ============================================

func TestGetLogSource(t *testing.T) {
	cfg := &config.WAFConfig{
		WAFLogPath:       "/var/log/waf_audit.log",
		RateLimitLogPath: "/var/log/rate_limit.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		filePath string
		want     string
	}{
		{"/var/log/waf_audit.log", "waf"},
		{"/var/log/rate_limit.log", "rate_limit"},
		{"/some/other/file.log", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			got := monitor.getLogSource(tt.filePath)
			if got != tt.want {
				t.Errorf("getLogSource(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

// ============================================
// banIP 去重逻辑测试
// ============================================

func TestBanIP_NewBan(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// 验证 IP 被封禁
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP should be banned")
	}

	// 验证封禁记录
	if len(monitor.bannedIPs) != 1 {
		t.Errorf("bannedIPs should have 1 entry, got %d", len(monitor.bannedIPs))
	}

	record := monitor.bannedIPs["1.2.3.4"]
	if record.Expiry.Before(time.Now()) {
		t.Error("expiry should be in the future")
	}

	// 验证 XDP 被调用
	addedIPs := mockXDP.getAddedIPs()
	if _, ok := addedIPs["1.2.3.4"]; !ok {
		t.Error("XDP AddRuleWithSource should have been called with IP 1.2.3.4")
	}
	if addedIPs["1.2.3.4"] != sourceMaskWAF {
			t.Errorf("source mask should be sourceMaskWAF (%d), got %d", sourceMaskWAF, addedIPs["1.2.3.4"])
	}
}

func TestBanIP_DuplicateBanSkipped(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 第一次封禁
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// 立即再次封禁同一 IP（封禁期内）
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// XDP 应该只被调用一次
	if mockXDP.addCallCount != 1 {
		t.Errorf("AddRuleWithSource should be called once, got %d calls", mockXDP.addCallCount)
	}

	// 验证只有一个封禁记录
	if len(monitor.bannedIPs) != 1 {
		t.Errorf("bannedIPs should have 1 entry, got %d", len(monitor.bannedIPs))
	}
}

func TestBanIP_ReBanAfterExpiry(t *testing.T) {
	cfg := testConfig(1) // 1 秒封禁时长
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 第一次封禁
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// 等待封禁过期
	time.Sleep(1100 * time.Millisecond)

	// 过期后再次封禁
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// XDP 应该被调用两次（一次初始，一次过期后重封）
	if mockXDP.addCallCount != 2 {
		t.Errorf("AddRuleWithSource should be called twice, got %d calls", mockXDP.addCallCount)
	}

	// 验证 IP 仍然被封禁
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP should be banned again after re-ban")
	}
}

func TestBanIP_MultipleDifferentIPs(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	ips := []string{"1.2.3.4", "5.6.7.8", "10.20.30.40"}
	for _, ip := range ips {
		monitor.banIP(ip, "/logs/rate_limit.log")
	}

	// 验证所有 IP 都被封禁
	for _, ip := range ips {
		if !monitor.IsBanned(ip) {
			t.Errorf("IP %s should be banned", ip)
		}
	}

	// 验证封禁数量
	if monitor.GetBanCount() != 3 {
		t.Errorf("GetBanCount should return 3, got %d", monitor.GetBanCount())
	}

	// 验证 XDP 被调用了 3 次
	if mockXDP.addCallCount != 3 {
		t.Errorf("AddRuleWithSource should be called 3 times, got %d", mockXDP.addCallCount)
	}
}

func TestBanIP_XDPError(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	mockXDP.addErr = fmt.Errorf("xdp operation failed")
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")

	// XDP 失败，IP 不应被封禁
	if monitor.IsBanned("1.2.3.4") {
		t.Error("IP should not be banned when XDP fails")
	}
	if len(monitor.bannedIPs) != 0 {
		t.Errorf("bannedIPs should be empty, got %d entries", len(monitor.bannedIPs))
	}
}

// ============================================
// cleanup 过期清理测试
// ============================================

func TestCleanup_RemovesExpiredBans(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 手动添加一个已过期的封禁记录
	now := time.Now()
	monitor.bannedIPs["1.2.3.4"] = IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-1 * time.Hour), // 已过期
	}

	// 添加一个未过期的封禁记录
	monitor.bannedIPs["5.6.7.8"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(1 * time.Hour), // 未过期
	}

	// 执行清理
	monitor.cleanup()

	// 已过期的应被清理
	if monitor.IsBanned("1.2.3.4") {
		t.Error("Expired IP 1.2.3.4 should be cleaned up")
	}

	// 未过期的应保留
	if !monitor.IsBanned("5.6.7.8") {
		t.Error("Non-expired IP 5.6.7.8 should still be banned")
	}

	// 封禁数量应为 1
	if monitor.GetBanCount() != 1 {
		t.Errorf("GetBanCount should return 1, got %d", monitor.GetBanCount())
	}

	// 验证 XDP 清理被调用了一次（只清理过期的那条）
	if mockXDP.removeCallCount != 1 {
		t.Errorf("UpdateRuleSourceMask should be called once for expired IP, got %d", mockXDP.removeCallCount)
	}

	// 验证 XDP 清理使用正确的 mask
	removed := mockXDP.getRemovedSources()
	if removed["1.2.3.4"] != sourceMaskWAF {
		t.Errorf("should remove sourceMaskWAF for expired IP, got %d", removed["1.2.3.4"])
	}
}

func TestCleanup_RemovesXDPRuleForExpiredIP(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 添加多个已过期记录
	now := time.Now()
	expiredIPs := []string{"1.2.3.4", "5.6.7.8", "10.20.30.40"}
	for _, ip := range expiredIPs {
		monitor.bannedIPs[ip] = IPBanRecord{
			BannedAt: now.Add(-2 * time.Hour),
			Expiry:   now.Add(-1 * time.Hour),
		}
	}

	// 执行清理
	monitor.cleanup()

	// 验证所有过期 IP 被清理
	if len(monitor.bannedIPs) != 0 {
		t.Errorf("all expired IPs should be cleaned, got %d remaining", len(monitor.bannedIPs))
	}

	// 验证 XDP 清理被调用了 3 次
	if mockXDP.removeCallCount != 3 {
		t.Errorf("UpdateRuleSourceMask should be called 3 times, got %d", mockXDP.removeCallCount)
	}
}

func TestCleanup_NoExpiredBans(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 添加未过期的记录
	now := time.Now()
	monitor.bannedIPs["1.2.3.4"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(1 * time.Hour),
	}

	monitor.cleanup()

	// 不应有变化
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("Non-expired IP should still be banned")
	}
	if mockXDP.removeCallCount != 0 {
		t.Errorf("UpdateRuleSourceMask should not be called when no bans are expired, got %d", mockXDP.removeCallCount)
	}
}

func TestCleanup_EmptyBans(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 空的封禁列表，清理不应出错
	monitor.cleanup()

	if monitor.GetBanCount() != 0 {
		t.Error("ban count should be 0")
	}
	if mockXDP.removeCallCount != 0 {
		t.Error("no XDP removal should occur for empty ban list")
	}
}

// ============================================
// GetBannedIPs / GetBanCount / IsBanned 测试
// ============================================

func TestGetBannedIPs_ReturnsOnlyActive(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	now := time.Now()

	// 活跃的封禁
	monitor.bannedIPs["1.2.3.4"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(1 * time.Hour),
	}
	monitor.bannedIPs["5.6.7.8"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(2 * time.Hour),
	}

	// 已过期的封禁（但仍在 map 中）
	monitor.bannedIPs["10.20.30.40"] = IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-1 * time.Hour),
	}

	ips := monitor.GetBannedIPs()
	if len(ips) != 2 {
		t.Errorf("GetBannedIPs should return 2 active IPs, got %d", len(ips))
	}

	// 验证返回的 IP 是活跃的
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}
	if !ipSet["1.2.3.4"] || !ipSet["5.6.7.8"] {
		t.Error("GetBannedIPs should contain active IPs 1.2.3.4 and 5.6.7.8")
	}
	if ipSet["10.20.30.40"] {
		t.Error("GetBannedIPs should not contain expired IP 10.20.30.40")
	}
}

func TestGetBanCount(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 空列表
	if monitor.GetBanCount() != 0 {
		t.Error("empty monitor should have 0 bans")
	}

	now := time.Now()
	monitor.bannedIPs["1.2.3.4"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(1 * time.Hour),
	}
	monitor.bannedIPs["10.20.30.40"] = IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-1 * time.Hour),
	}

	if monitor.GetBanCount() != 1 {
		t.Errorf("GetBanCount should return 1 (only active), got %d", monitor.GetBanCount())
	}
}

func TestIsBanned(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 不存在的 IP
	if monitor.IsBanned("1.2.3.4") {
		t.Error("non-existent IP should not be banned")
	}

	now := time.Now()

	// 活跃封禁
	monitor.bannedIPs["1.2.3.4"] = IPBanRecord{
		BannedAt: now,
		Expiry:   now.Add(1 * time.Hour),
	}
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("active IP should be banned")
	}

	// 已过期封禁
	monitor.bannedIPs["5.6.7.8"] = IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-1 * time.Hour),
	}
	if monitor.IsBanned("5.6.7.8") {
		t.Error("expired IP should not be banned")
	}
}

// ============================================
// filePos 多文件独立性测试
// ============================================

func TestFilePos_IndependentPerFile(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	fileA := "/logs/waf_audit.log"
	fileB := "/logs/rate_limit.log"

	// 模拟两个文件分别有不同的读取位置
	monitor.filePos[fileA] = 1024
	monitor.filePos[fileB] = 2048

	// 验证位置独立
	if monitor.filePos[fileA] == monitor.filePos[fileB] {
		t.Error("file positions for different files should be independent")
	}
	if monitor.filePos[fileA] != 1024 {
		t.Errorf("filePos[%s] should be 1024, got %d", fileA, monitor.filePos[fileA])
	}
	if monitor.filePos[fileB] != 2048 {
		t.Errorf("filePos[%s] should be 2048, got %d", fileB, monitor.filePos[fileB])
	}

	// 更新一个文件的位置不应影响另一个
	monitor.filePos[fileA] = 2048
	if monitor.filePos[fileB] != 2048 {
		t.Errorf("updating filePos[%s] should not affect filePos[%s]", fileA, fileB)
	}
}

// ============================================
// readLogFile 文件轮转测试
// ============================================

func TestReadLogFile_FileRotation(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 创建临时目录和文件
	tmpDir := t.TempDir()
	wafLogPath := filepath.Join(tmpDir, "waf_audit.log")
	rateLimitLogPath := filepath.Join(tmpDir, "rate_limit.log")

	// 更新配置使用临时路径
	cfg.WAFLogPath = wafLogPath
	cfg.RateLimitLogPath = rateLimitLogPath

	// 写入初始日志内容（较长）
	initialContent := "1.2.3.4 - first request - some additional context info here\n"
	if err := os.WriteFile(wafLogPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write initial log: %v", err)
	}

	// 模拟读取，设置 filePos 到文件末尾
	if err := monitor.readLogFile(wafLogPath); err != nil {
		t.Fatalf("readLogFile failed: %v", err)
	}

	// 验证 filePos 已更新
	initialSize := int64(len(initialContent))
	if monitor.filePos[wafLogPath] != initialSize {
		t.Errorf("filePos should be %d after reading, got %d", initialSize, monitor.filePos[wafLogPath])
	}

	// 模拟文件轮转：写入更小的新内容（模拟日志轮转后新文件从空开始）
	rotatedContent := "5.6.7.8 - rotated\n"
	if err := os.WriteFile(wafLogPath, []byte(rotatedContent), 0644); err != nil {
		t.Fatalf("failed to write rotated log: %v", err)
	}

	// 再次读取
	if err := monitor.readLogFile(wafLogPath); err != nil {
		t.Fatalf("readLogFile failed after rotation: %v", err)
	}

	// 验证：轮转后新 IP 应被正确读取并封禁
	if !monitor.IsBanned("5.6.7.8") {
		t.Error("IP 5.6.7.8 from rotated log should be banned")
	}
}

func TestReadLogFile_NonExistentFile(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 读取不存在的文件不应出错
	err := monitor.readLogFile("/nonexistent/path/file.log")
	if err != nil {
		t.Errorf("readLogFile should not error for non-existent file, got: %v", err)
	}
}

func TestReadLogFile_IncrementalReading(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 创建临时文件
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	cfg.WAFLogPath = logPath

	// 第一次写入
	content1 := "1.2.3.4 - request 1\n"
	if err := os.WriteFile(logPath, []byte(content1), 0644); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// 第一次读取
	if err := monitor.readLogFile(logPath); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if mockXDP.addCallCount != 1 {
		t.Errorf("should have 1 XDP call after first read, got %d", mockXDP.addCallCount)
	}

	// 追加更多内容
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open for append: %v", err)
	}
	f.WriteString("5.6.7.8 - request 2\n")
	f.Close()

	// 第二次读取（增量）
	if err := monitor.readLogFile(logPath); err != nil {
		t.Fatalf("second read failed: %v", err)
	}

	// 应该只有 2 次调用（每个新 IP 一次）
	if mockXDP.addCallCount != 2 {
		t.Errorf("should have 2 XDP calls after incremental read, got %d", mockXDP.addCallCount)
	}
}

// ============================================
// Stop 测试
// ============================================

func TestStop_WithoutStart(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// Stop 在未 Start 的情况下不应 panic
	monitor.Stop()
}

// ============================================
// 并发安全测试
// ============================================

func TestConcurrentBanAndQuery(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	var wg sync.WaitGroup
	const goroutines = 10
	const opsPerGoroutine = 100

	// 并发写入
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := fmt.Sprintf("10.%d.%d.1", id, j)
				monitor.banIP(ip, "/logs/waf_audit.log")
			}
		}(i)
	}

	// 并发读取
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := fmt.Sprintf("10.%d.%d.1", id, j)
				_ = monitor.IsBanned(ip)
				_ = monitor.GetBanCount()
				_ = monitor.GetBannedIPs()
			}
		}(i)
	}

	wg.Wait()

	// 验证没有 panic 发生（如果执行到这里说明并发安全）
	if monitor.GetBanCount() == 0 {
		t.Error("should have some banned IPs after concurrent operations")
	}
}

// ============================================
// 综合集成测试
// ============================================

func TestFullWorkflow_BanAndCleanup(t *testing.T) {
	cfg := testConfig(1) // 1 秒封禁时长
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	// 1. 封禁几个 IP
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")
	monitor.banIP("5.6.7.8", "/logs/rate_limit.log")

	// 验证封禁
	if monitor.GetBanCount() != 2 {
		t.Fatalf("expected 2 bans, got %d", monitor.GetBanCount())
	}

	// 2. 等待过期
	time.Sleep(1100 * time.Millisecond)

	// 3. 执行清理
	monitor.cleanup()

	// 4. 验证清理后状态
	if monitor.GetBanCount() != 0 {
		t.Errorf("expected 0 bans after cleanup, got %d", monitor.GetBanCount())
	}

	// 5. 验证 XDP 添加和移除
	if mockXDP.addCallCount != 2 {
		t.Errorf("expected 2 XDP adds, got %d", mockXDP.addCallCount)
	}
	if mockXDP.removeCallCount != 2 {
		t.Errorf("expected 2 XDP removes during cleanup, got %d", mockXDP.removeCallCount)
	}

	// 6. 过期后可以重新封禁
	monitor.banIP("1.2.3.4", "/logs/waf_audit.log")
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP should be banned again after cleanup and re-ban")
	}
	if mockXDP.addCallCount != 3 {
		t.Errorf("expected 3 XDP adds (2 initial + 1 re-ban), got %d", mockXDP.addCallCount)
	}
}
