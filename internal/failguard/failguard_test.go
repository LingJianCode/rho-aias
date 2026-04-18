package failguard

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
)

// mockXDPRuleManager 是 XDPRuleManager 接口的 mock 实现
type mockXDPRuleManager struct {
	mu             sync.Mutex
	addedIPs       map[string]uint32
	addErr         error
	addCallCount   int
	removeCallCount int
}

func newMockXDPRuleManager() *mockXDPRuleManager {
	return &mockXDPRuleManager{
		addedIPs: make(map[string]uint32),
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
	return 0, true, true, nil
}

// ============================================
// 真实日志解析测试
// ============================================

const realSSHLogNormal = `2026-04-01T09:47:45.292541+08:00 localhost sshd[419683]: Failed password for root from 106.54.24.131 port 35340 ssh2`

const realSSHLogPreauth = `2026-04-01T09:47:45.292541+08:00 localhost sshd[419683]: Connection closed by authenticating user root 106.54.24.131 port 35340 [preauth]`

const realSSHLogInvalidUser = `2026-04-01T09:47:46.123456+08:00 localhost sshd[419684]: Invalid user admin from 192.168.1.100 port 52341`

const realSSHLogAccepted = `2026-04-01T09:47:50.000000+08:00 localhost sshd[419685]: Accepted password for root from 10.0.0.1 port 49152 ssh2`

// ============================================
// matchFail / matchIgnore 测试
// ============================================

func TestMatchFail_Aggressive(t *testing.T) {
	// aggressive = normal + ddos + aggressive，是所有模式的超集
	cfg := &config.FailGuardConfig{
		Mode:       "aggressive",
		MaxRetry:   5,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	tests := []struct {
		name    string
		line    string
		want    string // 期望提取的 IP，空表示不匹配
	}{
		// --- normal 模式规则 ---
		{
			name: "Failed password",
			line: realSSHLogNormal,
			want: "106.54.24.131",
		},
		{
			name: "Invalid user",
			line: realSSHLogInvalidUser,
			want: "192.168.1.100",
		},
		{
			name: "Accepted (success, should not match)",
			line: realSSHLogAccepted,
			want: "",
		},
		{
			name: "Empty line",
			line: "",
			want: "",
		},
		{
			name: "PAM auth failure",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4",
			want: "1.2.3.4",
		},
		{
			name: "Maximum authentication attempts",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Maximum authentication attempts exceeded for root from 5.6.7.8 port 22 ssh2",
			want: "5.6.7.8",
		},
		{
			name: "Illegal user",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Illegal user test from 10.20.30.40",
			want: "10.20.30.40",
		},
		{
			name: "Disconnected from authenticating user",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Disconnected from authenticating user admin 1.2.3.4 port 22",
			want: "1.2.3.4",
		},
		// --- ddos 模式规则 ---
		{
			name: "Connection closed preauth",
			line: realSSHLogPreauth,
			want: "106.54.24.131",
		},
		{
			name: "Did not receive identification string",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Did not receive identification string from 10.0.0.1 port 22",
			want: "10.0.0.1",
		},
		{
			name: "Timeout before authentication",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Timeout before authentication for 10.0.0.2",
			want: "10.0.0.2",
		},
		{
			name: "Connection reset by authenticating user preauth",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Connection reset by authenticating user admin 10.0.0.3 port 22 [preauth]",
			want: "10.0.0.3",
		},
		// --- aggressive 模式专属规则 ---
		{
			name: "Bad protocol version",
			line: `2026-04-01T10:00:00+08:00 localhost sshd[123] Bad protocol version identification 'SSH-1.99-OpenSSH' from 10.0.0.1`,
			want: "10.0.0.1",
		},
		{
			name: "Unable to negotiate key exchange",
			line: `2026-04-01T10:00:00+08:00 localhost sshd[123] fatal: Unable to negotiate with 10.0.0.2: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1`,
			want: "10.0.0.2",
		},
		{
			name: "Unable to negotiate cipher",
			line: `2026-04-01T10:00:00+08:00 localhost sshd[123] fatal: Unable to negotiate with 10.0.0.3: no matching cipher found`,
			want: "10.0.0.3",
		},
		{
			name: "banner exchange",
			line: `2026-04-01T10:00:00+08:00 localhost sshd[123] banner exchange: Connection from 10.0.0.4 port 22: invalid format`,
			want: "10.0.0.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := monitor.matchFail(tt.line)
			if ip != tt.want {
				t.Errorf("matchFail() = %q, want %q", ip, tt.want)
			}
		})
	}
}

func TestMatchIgnore(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   5,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	tests := []struct {
		name    string
		line    string
		want    bool
	}{
		{
			name: "Accepted password (should ignore)",
			line: realSSHLogAccepted,
			want: true,
		},
		{
			name: "Connection from (normal, should ignore)",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Connection from 10.0.0.1 port 22",
			want: true,
		},
		{
			name: "Disconnected (non-preauth, should ignore)",
			line: "2026-04-01T10:00:00+08:00 localhost sshd[123] Disconnected from 10.0.0.1",
			want: true,
		},
		{
			name: "Failed password (should NOT ignore)",
			line: realSSHLogNormal,
			want: false,
		},
		{
			name: "Connection closed preauth (should NOT ignore)",
			line: realSSHLogPreauth,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitor.matchIgnore(tt.line)
			if got != tt.want {
				t.Errorf("matchIgnore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIgnoredIP(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   5,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
		IgnoreIPs:  []string{"10.0.0.0/8", "172.16.0.0/12"},
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", false},
		{"106.54.24.131", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := monitor.isIgnoredIP(tt.ip)
			if got != tt.want {
				t.Errorf("isIgnoredIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ============================================
// addFailureAndCheck 滑动窗口测试
// ============================================

func TestAddFailureAndCheck_ReachesThreshold(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   3,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	// 前两次不应触发封禁
	if monitor.addFailureAndCheck("1.2.3.4") {
		t.Error("should not trigger ban after 1st failure")
	}
	if monitor.addFailureAndCheck("1.2.3.4") {
		t.Error("should not trigger ban after 2nd failure")
	}
	// 第三次应触发
	if !monitor.addFailureAndCheck("1.2.3.4") {
		t.Error("should trigger ban after 3rd failure")
	}
}

func TestAddFailureAndCheck_WindowExpiry(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   3,
		FindTime:   1, // 1 秒窗口
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	// 添加 2 次失败
	monitor.addFailureAndCheck("1.2.3.4")
	monitor.addFailureAndCheck("1.2.3.4")

	// 等待窗口过期
	time.Sleep(1100 * time.Millisecond)

	// 再添加 2 次（窗口内只有 2 次，不算之前的）
	monitor.addFailureAndCheck("1.2.3.4")
	if monitor.addFailureAndCheck("1.2.3.4") {
		t.Error("should not trigger ban: old failures expired, only 2 in new window")
	}
	// 第三次触发
	if !monitor.addFailureAndCheck("1.2.3.4") {
		t.Error("should trigger ban after 3 failures in new window")
	}
}

func TestAddFailureAndCheck_IndependentPerIP(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   3,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	// 不同 IP 独立计数
	ban1 := monitor.addFailureAndCheck("1.1.1.1")
	ban2 := monitor.addFailureAndCheck("1.1.1.1")
	ban3 := monitor.addFailureAndCheck("2.2.2.2")
	ban4 := monitor.addFailureAndCheck("1.1.1.1")

	if ban1 || ban2 || ban3 {
		t.Errorf("first 3 failures should not trigger: ban1=%v ban2=%v ban3=%v", ban1, ban2, ban3)
	}
	if !ban4 {
		t.Error("1.1.1.1: 3rd failure should trigger ban")
	}
	if monitor.addFailureAndCheck("2.2.2.2") {
		t.Error("2.2.2.2: only 2 failures, should NOT trigger")
	}
}

// ============================================
// handleLine 集成测试
// ============================================

func TestHandleLine_AggressiveMode(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:        "aggressive",
		MaxRetry:    1, // 1 次就封
		FindTime:    600,
		BanDuration: 1800,
		LogPath:     "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	// normal 规则：Failed password
	ip, sourceMask, reason, duration, shouldBan := monitor.handleLine(realSSHLogNormal)
	if !shouldBan {
		t.Fatal("should trigger ban for Failed password line")
	}
	if ip != "106.54.24.131" {
		t.Errorf("expected IP 106.54.24.131, got %s", ip)
	}
	if sourceMask != ebpfs.SourceMaskFailGuard {
		t.Errorf("expected sourceMask %d, got %d", ebpfs.SourceMaskFailGuard, sourceMask)
	}
	if reason != "SSH brute force" {
		t.Errorf("expected reason 'SSH brute force', got %s", reason)
	}
	if duration != 1800 {
		t.Errorf("expected duration 1800, got %d", duration)
	}

	// ddos 规则：Connection closed preauth
	ip, _, _, _, shouldBan = monitor.handleLine(realSSHLogPreauth)
	if !shouldBan {
		t.Fatal("should trigger ban for Connection closed preauth in aggressive mode")
	}
	if ip != "106.54.24.131" {
		t.Errorf("expected IP 106.54.24.131, got %s", ip)
	}

	// Accept 日志不应触发（被 ignore 规则过滤）
	_, _, _, _, shouldBan = monitor.handleLine(realSSHLogAccepted)
	if shouldBan {
		t.Error("Accepted line should not trigger ban")
	}
}

// ============================================
// 真实日志文件读取+封禁集成测试
// ============================================

func TestReadLogFile_RealSSHLog_Aggressive(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:        "aggressive",
		MaxRetry:    1, // 1 次就封
		FindTime:    600,
		BanDuration: 3600,
		LogPath:     "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	monitor.watcher.SetLineHandler(monitor.handleLine)

	if err := monitor.watcher.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer monitor.watcher.Stop()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "auth.log")

	content := realSSHLogNormal + "\n" + realSSHLogAccepted + "\n" + realSSHLogPreauth + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write log: %v", err)
	}

	if err := monitor.watcher.WatchLogFile(logPath); err != nil {
		t.Fatalf("WatchLogFile failed: %v", err)
	}

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("ReadLogFile failed: %v", err)
	}

	// Failed password 应触发封禁（normal 规则）
	if !monitor.IsBanned("106.54.24.131") {
		t.Error("106.54.24.131 should be banned from Failed password log")
	}

	// Accepted 不应封禁
	if monitor.IsBanned("10.0.0.1") {
		t.Error("10.0.0.1 should NOT be banned from Accepted log")
	}

	// 已封禁的 IP 重复出现不应重复封禁（preauth 日志同 IP）
	if mockXDP.addCallCount != 1 {
		t.Errorf("expected 1 XDP call, got %d", mockXDP.addCallCount)
	}
}

func TestReadLogFile_RealSSHPreauth_Aggressive(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:        "aggressive",
		MaxRetry:    1,
		FindTime:    600,
		BanDuration: 3600,
		LogPath:     "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	monitor.watcher.SetLineHandler(monitor.handleLine)

	if err := monitor.watcher.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer monitor.watcher.Stop()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "auth.log")

	content := realSSHLogPreauth + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write log: %v", err)
	}

	if err := monitor.watcher.WatchLogFile(logPath); err != nil {
		t.Fatalf("WatchLogFile failed: %v", err)
	}

	if err := monitor.watcher.ReadLogFile(logPath); err != nil {
		t.Fatalf("ReadLogFile failed: %v", err)
	}

	if !monitor.IsBanned("106.54.24.131") {
		t.Error("106.54.24.131 should be banned from preauth log in aggressive mode")
	}
}

// ============================================
// cleanupFailures 测试
// ============================================

func TestCleanupFailures(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   5,
		FindTime:   1, // 1 秒窗口
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	// 添加失败记录
	monitor.addFailureAndCheck("1.2.3.4")
	monitor.addFailureAndCheck("5.6.7.8")

	// 等待窗口过期
	time.Sleep(1100 * time.Millisecond)

	// 清理
	monitor.cleanupFailures()

	// 验证记录被清理（不需要 panic）
	if len(monitor.failures) != 0 {
		t.Errorf("all failure records should be cleaned, got %d remaining", len(monitor.failures))
	}
}

// ============================================
// Stop 测试
// ============================================

func TestStop_WithoutStart(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   5,
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	monitor.Stop() // 不应 panic
}

// ============================================
// 并发安全测试
// ============================================

func TestConcurrentHandleLine(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Mode:       "normal",
		MaxRetry:   1, // 1 次就封
		FindTime:   600,
		BanDuration: 3600,
		LogPath:    "/var/log/auth.log",
	}
	mockXDP := newMockXDPRuleManager()
	monitor := NewManager(cfg, mockXDP, context.Background(), nil, nil, nil)

	var wg sync.WaitGroup
	const goroutines = 10
	const opsPerGoroutine = 100

	// 并发封禁不同 IP
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := fmt.Sprintf("10.%d.%d.1", id, j)
				monitor.watcher.BanIP(ip, ebpfs.SourceMaskFailGuard, "concurrent", 3600)
			}
		}(i)
	}

	// 并发查询
	for i := 0; i < goroutines; i++ {
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

	// 验证没有 panic（到达这里说明并发安全）
	if monitor.GetBanCount() == 0 {
		t.Error("should have some banned IPs after concurrent operations")
	}
}
