package ratelimit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/watcher"
)

// mockXDPRuleManager 是 XDPRuleManager 接口的 mock 实现，用于单元测试
type mockXDPRuleManager struct {
	mu              sync.Mutex
	addedIPs        map[string]uint32 // 记录通过 AddRuleWithSource 添加的 IP 及其 sourceMask
	removedSources  map[string]uint32 // 记录通过 UpdateRuleSourceMask 移除的来源
	addErr          error             // AddRuleWithSource 返回的错误
	removeErr       error             // UpdateRuleSourceMask 返回的错误
	addCallCount    int               // AddRuleWithSource 调用次数
	removeCallCount int               // UpdateRuleSourceMask 调用次数
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

// testConfig 返回测试用的 RateLimit 配置
func testConfig(banDuration int) *config.RateLimitConfig {
	return &config.RateLimitConfig{
		Enabled:     true,
		LogPath:     "/logs/rate_limit.log",
		BanDuration: banDuration,
	}
}

// ============================================
// 真实日志样本
// ============================================

const realRateLimitLog = `{"level":"warn","ts":1743500924.725,"logger":"http.handlers.rate_limit","msg":"rate limit exceeded","remote_ip":"192.168.1.100","request":{"method":"GET","uri":"/api/data"},"extra":{"limit":100,"window":60,"remaining":0}}`

const realRateLimitLogNoIP = `{"level":"warn","ts":1743500924.725,"logger":"http.handlers.rate_limit","msg":"rate limit exceeded","request":{"method":"GET","uri":"/api/data"}}`

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

	if monitor.cfg != cfg {
		t.Error("cfg not set correctly")
	}
	if monitor.watcher.GetFilePos() == nil {
		t.Error("filePos should be initialized as non-nil map")
	}
	if monitor.watcher == nil {
		t.Error("watcher should be initialized")
	}
	if monitor.ipRegex == nil {
		t.Error("ipRegex should be initialized")
	}
	if len(monitor.watcher.GetFilePos()) != 0 {
		t.Errorf("filePos should be empty, got %d entries", len(monitor.watcher.GetFilePos()))
	}
	if monitor.watcher.GetBanCount() != 0 {
		t.Errorf("bannedIPs should be empty, got %d entries", monitor.watcher.GetBanCount())
	}
}

func TestNewMonitor_CreatesChildContext(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	monitor := NewMonitor(cfg, mockXDP, parentCtx)

	childCtx := monitor.watcher.Context()
	if childCtx == nil {
		t.Fatal("child context should not be nil")
	}

	parentCancel()
	select {
	case <-childCtx.Done():
	default:
		t.Fatal("child context should be done after parent cancel")
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
		name string
		line string
		want string
	}{
		{"empty line", "", ""},
		{"no IP in line", "this line has no ip address", ""},
		{"invalid IP format", "ip: 999.999.999.999", ""},
		{"partial IP", "ip: 192.168.1", ""},
		{"JSON without remote_ip", realRateLimitLogNoIP, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractIP_JsonRemoteIP(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "Rate limit log with remote_ip",
			line: `{"remote_ip":"1.2.3.4","msg":"rate limit exceeded"}`,
			want: "1.2.3.4",
		},
		{
			name: "Real rate limit log",
			line: realRateLimitLog,
			want: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractIP_FallbackToRegex(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "Non-JSON line with single IP",
			line: "rate limited: 10.20.30.40 exceeded threshold",
			want: "10.20.30.40",
		},
		{
			name: "Non-JSON line with multiple IPs - should take first",
			line: "rate limited client 10.0.0.1 proxied from 10.0.0.2 exceeded",
			want: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.extractIP(tt.line)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
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
			got := monitor.extractIP(tt.line)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.line, got, tt.want)
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

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)

	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP should be banned")
	}

	record, exists := monitor.watcher.GetBanRecord("1.2.3.4")
	if !exists {
		t.Fatal("ban record should exist")
	}
	if record.Expiry.Before(time.Now()) {
		t.Error("expiry should be in the future")
	}
	if record.SourceMask != ebpfs.SourceMaskRateLimit {
		t.Errorf("record SourceMask should be ebpfs.SourceMaskRateLimit (%d), got %d", ebpfs.SourceMaskRateLimit, record.SourceMask)
	}

	addedIPs := mockXDP.getAddedIPs()
	if _, ok := addedIPs["1.2.3.4"]; !ok {
		t.Error("XDP AddRuleWithSource should have been called with IP 1.2.3.4")
	}
	if addedIPs["1.2.3.4"] != ebpfs.SourceMaskRateLimit {
		t.Errorf("source mask should be ebpfs.SourceMaskRateLimit (%d), got %d", ebpfs.SourceMaskRateLimit, addedIPs["1.2.3.4"])
	}
}

func TestBanIP_DuplicateBanSkipped(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)
	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)

	if mockXDP.addCallCount != 1 {
		t.Errorf("AddRuleWithSource should be called once, got %d calls", mockXDP.addCallCount)
	}
	if monitor.watcher.GetBanCount() != 1 {
		t.Errorf("bannedIPs should have 1 entry, got %d", monitor.watcher.GetBanCount())
	}
}

func TestBanIP_ReBanAfterExpiry(t *testing.T) {
	cfg := testConfig(1)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)
	time.Sleep(1100 * time.Millisecond)
	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)

	if mockXDP.addCallCount != 2 {
		t.Errorf("AddRuleWithSource should be called twice, got %d calls", mockXDP.addCallCount)
	}
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
		monitor.watcher.BanIP(ip, ebpfs.SourceMaskRateLimit, "rate limit ban", cfg.BanDuration)
	}

	for _, ip := range ips {
		if !monitor.IsBanned(ip) {
			t.Errorf("IP %s should be banned", ip)
		}
	}

	if monitor.GetBanCount() != 3 {
		t.Errorf("GetBanCount should return 3, got %d", monitor.GetBanCount())
	}
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

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)

	if monitor.IsBanned("1.2.3.4") {
		t.Error("IP should not be banned when XDP fails")
	}
	if monitor.watcher.GetBanCount() != 0 {
		t.Errorf("bannedIPs should be empty, got %d entries", monitor.watcher.GetBanCount())
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

	now := time.Now()
	monitor.watcher.SetBanRecordForTest("1.2.3.4", watcher.IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})
	monitor.watcher.SetBanRecordForTest("5.6.7.8", watcher.IPBanRecord{
		BannedAt: now, Expiry: now.Add(1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})

	monitor.watcher.CleanupExpiredBans()

	if monitor.IsBanned("1.2.3.4") {
		t.Error("Expired IP 1.2.3.4 should be cleaned up")
	}
	if !monitor.IsBanned("5.6.7.8") {
		t.Error("Non-expired IP 5.6.7.8 should still be banned")
	}
	if monitor.GetBanCount() != 1 {
		t.Errorf("GetBanCount should return 1, got %d", monitor.GetBanCount())
	}
	if mockXDP.removeCallCount != 1 {
		t.Errorf("UpdateRuleSourceMask should be called once, got %d", mockXDP.removeCallCount)
	}
	removed := mockXDP.getRemovedSources()
	if removed["1.2.3.4"] != ebpfs.SourceMaskRateLimit {
		t.Errorf("should remove ebpfs.SourceMaskRateLimit, got %d", removed["1.2.3.4"])
	}
}

func TestCleanup_NoExpiredBans(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	now := time.Now()
	monitor.watcher.SetBanRecordForTest("1.2.3.4", watcher.IPBanRecord{
		BannedAt: now, Expiry: now.Add(1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})

	monitor.watcher.CleanupExpiredBans()

	if !monitor.IsBanned("1.2.3.4") {
		t.Error("Non-expired IP should still be banned")
	}
	if mockXDP.removeCallCount != 0 {
		t.Errorf("UpdateRuleSourceMask should not be called, got %d", mockXDP.removeCallCount)
	}
}

func TestCleanup_EmptyBans(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.CleanupExpiredBans()

	if monitor.GetBanCount() != 0 {
		t.Error("ban count should be 0")
	}
	if mockXDP.removeCallCount != 0 {
		t.Error("no XDP removal should occur")
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
	monitor.watcher.SetBanRecordForTest("1.2.3.4", watcher.IPBanRecord{
		BannedAt: now, Expiry: now.Add(1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})
	monitor.watcher.SetBanRecordForTest("5.6.7.8", watcher.IPBanRecord{
		BannedAt: now, Expiry: now.Add(2 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})
	monitor.watcher.SetBanRecordForTest("10.20.30.40", watcher.IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})

	ips := monitor.GetBannedIPs()
	if len(ips) != 2 {
		t.Errorf("GetBannedIPs should return 2 active IPs, got %d", len(ips))
	}
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}
	if !ipSet["1.2.3.4"] || !ipSet["5.6.7.8"] {
		t.Error("GetBannedIPs should contain 1.2.3.4 and 5.6.7.8")
	}
	if ipSet["10.20.30.40"] {
		t.Error("GetBannedIPs should not contain expired IP 10.20.30.40")
	}
}

func TestIsBanned(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	if monitor.IsBanned("1.2.3.4") {
		t.Error("non-existent IP should not be banned")
	}

	now := time.Now()
	monitor.watcher.SetBanRecordForTest("1.2.3.4", watcher.IPBanRecord{
		BannedAt: now, Expiry: now.Add(1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("active IP should be banned")
	}

	monitor.watcher.SetBanRecordForTest("5.6.7.8", watcher.IPBanRecord{
		BannedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-1 * time.Hour), SourceMask: ebpfs.SourceMaskRateLimit,
	})
	if monitor.IsBanned("5.6.7.8") {
		t.Error("expired IP should not be banned")
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

	monitor.watcher.SetLineHandler(monitor.handleLine)

	if err := monitor.watcher.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer monitor.watcher.Stop()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "rate_limit.log")

	initialContent := `{"remote_ip":"1.2.3.4","msg":"rate limit exceeded"}
{"remote_ip":"2.3.4.5","msg":"rate limit exceeded"}
{"remote_ip":"3.4.5.6","msg":"rate limit exceeded"}
`
	if err := os.WriteFile(logPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write initial log: %v", err)
	}

	monitor.watcher.WatchLogFile(logPath)

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("readLogFile failed: %v", err)
	}

	initialSize := int64(len(initialContent))
	filePos := monitor.watcher.GetFilePos()
	if filePos[logPath] != initialSize {
		t.Errorf("filePos should be %d after reading, got %d", initialSize, filePos[logPath])
	}

	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP 1.2.3.4 from initial log should be banned")
	}

	rotatedContent := `{"remote_ip":"5.6.7.8","msg":"rate limit exceeded"}
`
	if err := os.WriteFile(logPath, []byte(rotatedContent), 0644); err != nil {
		t.Fatalf("failed to write rotated log: %v", err)
	}

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("readLogFile failed after rotation: %v", err)
	}

	if !monitor.IsBanned("5.6.7.8") {
		t.Error("IP 5.6.7.8 from rotated log should be banned")
	}
}

func TestReadLogFile_NonExistentFile(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	err := monitor.watcher.ReadLogFile("/nonexistent/path/file.log")
	if err != nil {
		t.Errorf("readLogFile should not error for non-existent file, got: %v", err)
	}
}

func TestReadLogFile_IncrementalReading(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.SetLineHandler(monitor.handleLine)

	if err := monitor.watcher.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer monitor.watcher.Stop()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	content1 := `{"remote_ip":"1.2.3.4","msg":"rate limit exceeded"}
`
	if err := os.WriteFile(logPath, []byte(content1), 0644); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	monitor.watcher.WatchLogFile(logPath)

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if mockXDP.addCallCount != 1 {
		t.Errorf("should have 1 XDP call after first read, got %d", mockXDP.addCallCount)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open for append: %v", err)
	}
	if _, err := f.WriteString(`{"remote_ip":"5.6.7.8","msg":"rate limit exceeded"}
`); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}
	f.Close()

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("second read failed: %v", err)
	}

	if mockXDP.addCallCount != 2 {
		t.Errorf("should have 2 XDP calls, got %d", mockXDP.addCallCount)
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

	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := fmt.Sprintf("10.%d.%d.1", id, j)
				monitor.watcher.BanIP(ip, ebpfs.SourceMaskRateLimit, "concurrent test", cfg.BanDuration)
			}
		}(i)
	}

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

	if monitor.GetBanCount() == 0 {
		t.Error("should have some banned IPs after concurrent operations")
	}
}

// ============================================
// 综合集成测试
// ============================================

func TestFullWorkflow_BanAndCleanup(t *testing.T) {
	cfg := testConfig(1)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "test ban", cfg.BanDuration)
	monitor.watcher.BanIP("5.6.7.8", ebpfs.SourceMaskRateLimit, "rate limit ban", cfg.BanDuration)

	if monitor.GetBanCount() != 2 {
		t.Fatalf("expected 2 bans, got %d", monitor.GetBanCount())
	}

	time.Sleep(1100 * time.Millisecond)

	monitor.watcher.CleanupExpiredBans()

	if monitor.GetBanCount() != 0 {
		t.Errorf("expected 0 bans after cleanup, got %d", monitor.GetBanCount())
	}
	if mockXDP.addCallCount != 2 {
		t.Errorf("expected 2 XDP adds, got %d", mockXDP.addCallCount)
	}
	if mockXDP.removeCallCount != 2 {
		t.Errorf("expected 2 XDP removes, got %d", mockXDP.removeCallCount)
	}

	monitor.watcher.BanIP("1.2.3.4", ebpfs.SourceMaskRateLimit, "re-ban", cfg.BanDuration)
	if !monitor.IsBanned("1.2.3.4") {
		t.Error("IP should be banned again after cleanup and re-ban")
	}
	if mockXDP.addCallCount != 3 {
		t.Errorf("expected 3 XDP adds, got %d", mockXDP.addCallCount)
	}
}

// ============================================
// 真实日志解析测试
// ============================================

func TestRealLog_RateLimitExtraction(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	ip := monitor.extractIP(realRateLimitLog)
	if ip != "192.168.1.100" {
		t.Errorf("extractIP() = %q, want '192.168.1.100'", ip)
	}
}

func TestRealLog_HandleLine(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	ip, sourceMask, reason, duration, shouldBan := monitor.handleLine(realRateLimitLog)
	if !shouldBan {
		t.Fatal("handleLine should return shouldBan=true for rate limit log")
	}
	if ip != "192.168.1.100" {
		t.Errorf("expected IP '192.168.1.100', got %s", ip)
	}
	if sourceMask != ebpfs.SourceMaskRateLimit {
		t.Errorf("expected sourceMask %d, got %d", ebpfs.SourceMaskRateLimit, sourceMask)
	}
	if reason != "banned from rate_limit log" {
		t.Errorf("expected reason 'banned from rate_limit log', got %s", reason)
	}
	if duration != 3600 {
		t.Errorf("expected duration 3600, got %d", duration)
	}
}

func TestRealLog_HandleLine_NoIP(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	monitor := NewMonitor(cfg, mockXDP, context.Background())

	_, _, _, _, shouldBan := monitor.handleLine(realRateLimitLogNoIP)
	if shouldBan {
		t.Error("handleLine should NOT ban when no IP can be extracted")
	}
}

func TestRealLog_ReadLogFile(t *testing.T) {
	cfg := testConfig(3600)
	mockXDP := newMockXDPRuleManager()
	ctx := context.Background()
	monitor := NewMonitor(cfg, mockXDP, ctx)

	monitor.watcher.SetLineHandler(monitor.handleLine)

	if err := monitor.watcher.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer monitor.watcher.Stop()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "rate_limit.log")

	if err := os.WriteFile(logPath, []byte(realRateLimitLog+"\n"), 0644); err != nil {
		t.Fatalf("failed to write log: %v", err)
	}

	monitor.watcher.WatchLogFile(logPath)

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("ReadLogFile failed: %v", err)
	}

	if !monitor.IsBanned("192.168.1.100") {
		t.Error("192.168.1.100 should be banned from rate limit log")
	}
	if mockXDP.addCallCount != 1 {
		t.Errorf("expected 1 XDP call, got %d", mockXDP.addCallCount)
	}
}
