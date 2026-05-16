package failguard

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"rho-aias/internal/config"
)

// ============================================
// Mock 实现
// ============================================

type mockEBPFManager struct {
	mu       sync.Mutex
	addedIPs map[string]uint32
	addErr   error
}

func newMockEBPFManager() *mockEBPFManager {
	return &mockEBPFManager{
		addedIPs: make(map[string]uint32),
	}
}

func (m *mockEBPFManager) AddRuleWithSourceAndExpiry(value string, sourceMask uint32, duration int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addErr != nil {
		return m.addErr
	}
	m.addedIPs[value] = sourceMask
	return nil
}

// ============================================
// BanFilter 测试（使用手动构造的 WhitelistChecker 兼容接口）
// ============================================

type testWhitelistChecker struct {
	whitelist map[string]bool
}

func newTestWL(ips ...string) *testWhitelistChecker {
	wl := &testWhitelistChecker{whitelist: make(map[string]bool)}
	for _, ip := range ips {
		wl.whitelist[ip] = true
	}
	return wl
}

func (m *testWhitelistChecker) IsWhitelisted(ip string) bool {
	// 简单实现：精确匹配 + CIDR 检查
	if m.whitelist[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for cidr := range m.whitelist {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

// testBanFilter 包装 testWhitelistChecker 以匹配 BanFilter 的需求
func newTestBanFilter(wl *testWhitelistChecker) *BanFilter {
	// 由于 BanFilter 内部使用 manual.WhitelistChecker 接口，
	// 测试中我们通过构造函数注入一个兼容的检查器
	// 这里用类型断言绕过：实际上 BanFilter 只依赖 IsWhitelisted 方法
	return &BanFilter{checker: nil} // 测试中直接测试 ShouldBlock 逻辑
}

func TestBanFilter_ShouldBlock(t *testing.T) {
	wl := newTestWL("10.0.0.0/8")
	// 通过构造带 IsWhitelisted 方法的匿名结构体绕过具体类型检查
	filter := &BanFilter{
		checker: wl, // testWhitelistChecker 满足接口契约（有 IsWhelisted(string) bool 方法）
	}

	tests := []struct {
		ip   string
		want bool // true = 应该封禁
	}{
		{"1.2.3.4", true},
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := filter.ShouldBlock(tt.ip)
			if got != tt.want {
				t.Errorf("ShouldBlock(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestBanFilter_NilChecker(t *testing.T) {
	filter := NewBanFilter(nil)
	if !filter.ShouldBlock("any_ip") {
		t.Error("nil checker should always return true (should block)")
	}
}

// ============================================
// FormatRemoteIP 测试
// ============================================

func TestFormatRemoteIP(t *testing.T) {
	tests := []struct {
		raw  uint32 // binary.LittleEndian 反序列化自 ringbuf 网络字节序后的值
		want string
	}{
		{0x01020304, "4.3.2.1"},       // 内存 [04,03,02,01](BE) → LE读为 0x01020304
		{0x00000000, "0.0.0.0"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x0100007F, "127.0.0.1"},      // 内存 [7F,00,00,01](BE) → LE读为 0x0100007F
		{0x8318366A, "106.54.24.131"},  // 内存 [6A,36,18,83](BE) → LE读为 0x8318366A
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatRemoteIP(tt.raw)
			if got != tt.want {
				t.Errorf("FormatRemoteIP(%#08x) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// ============================================
// BanManager 滑动窗口测试
// ============================================

func TestBanManager_RegisterFailure_Threshold(t *testing.T) {
	bm := NewBanManager(3, 600, 3600, nil)
	ip := uint32(0x6A382483)

	if shouldBan, _ := bm.RegisterFailure(ip); shouldBan {
		t.Error("1st failure should not trigger ban")
	}
	if shouldBan, _ := bm.RegisterFailure(ip); shouldBan {
		t.Error("2nd failure should not trigger ban")
	}
	if shouldBan, _ := bm.RegisterFailure(ip); !shouldBan {
		t.Error("3rd failure should trigger ban")
	}
}

func TestBanManager_RegisterFailure_WindowExpiry(t *testing.T) {
	bm := NewBanManager(3, 1, 3600, nil)
	ip := uint32(0x01020304)

	bm.RegisterFailure(ip)
	bm.RegisterFailure(ip)
	time.Sleep(1100 * time.Millisecond)

	bm.RegisterFailure(ip)
	if shouldBan, _ := bm.RegisterFailure(ip); shouldBan {
		t.Error("only 2 failures in new window, should not trigger")
	}
	if shouldBan, _ := bm.RegisterFailure(ip); !shouldBan {
		t.Error("3rd failure in new window should trigger")
	}
}

func TestBanManager_RegisterFailure_AlreadyBanned(t *testing.T) {
	bm := NewBanManager(2, 600, 3600, nil)
	ip := uint32(0x0A000001)

	bm.RegisterFailure(ip)
	if shouldBan, _ := bm.RegisterFailure(ip); !shouldBan {
		t.Fatal("should trigger ban on 2nd failure")
	}

	_, expAt := bm.RegisterFailure(ip)
	if expAt.IsZero() {
		t.Error("already banned IP should return expiry time, not zero")
	}
}

func TestBanManager_ForceBan(t *testing.T) {
	bm := NewBanManager(5, 600, 3600, nil)
	ip := uint32(0xC0A80101)

	expAt := bm.ForceBan(ip)
	if expAt.IsZero() {
		t.Error("ForceBan should return non-zero expiry for non-permanent ban")
	}
	if !bm.IsBanned(ip) {
		t.Error("ForceBan should mark IP as banned")
	}
}

func TestBanManager_IsBanned_PerIP(t *testing.T) {
	bm := NewBanManager(1, 600, 3600, nil)

	ip1 := uint32(0x01010101)
	ip2 := uint32(0x02020202)

	bm.ForceBan(ip1)

	if !bm.IsBanned(ip1) {
		t.Error("ip1 should be banned")
	}
	if bm.IsBanned(ip2) {
		t.Error("ip2 should NOT be banned")
	}
}

func TestBanManager_IsBannedByString(t *testing.T) {
	bm := NewBanManager(1, 600, 3600, nil)
	bm.ForceBan(uint32(0x8318366A)) // 106.54.24.131 内存 [6A,36,18,83](BE) → LE读为 0x8318366A

	if !bm.IsBannedByString("106.54.24.131") {
		t.Error("106.54.24.131 should be banned")
	}
	if bm.IsBannedByString("1.2.3.4") {
		t.Error("1.2.3.4 should NOT be banned")
	}
	if bm.IsBannedByString("invalid") {
		t.Error("invalid IP string should return false")
	}
}

func TestBanManager_Expired(t *testing.T) {
	bm := NewBanManager(5, 600, 1, nil)
	// 10.0.0.2 内存大端 [0A,00,00,02] → LE反序列化为 0x0200000A
	ip := uint32(0x0200000A)

	bm.ForceBan(ip)

	expired := bm.Expired()
	if len(expired) != 0 {
		t.Errorf("no bans should expire immediately, got %d", len(expired))
	}

	time.Sleep(1100 * time.Millisecond)

	expired = bm.Expired()
	if len(expired) != 1 {
		t.Errorf("expected 1 expired ban, got %d", len(expired))
	} else if expired[0] != "10.0.0.2" {
		t.Errorf("expired IP should be 10.0.0.2, got %s", expired[0])
	}
}

func TestBanManager_GetBannedIPs(t *testing.T) {
	bm := NewBanManager(1, 600, 3600, nil)

	ip1 := uint32(0x01010101)
	ip2 := uint32(0x02020202)

	bm.ForceBan(ip1)
	bm.ForceBan(ip2)

	ips := bm.GetBannedIPs()
	if len(ips) != 2 {
		t.Fatalf("expected 2 banned IPs, got %d", len(ips))
	}

	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}
	if !ipSet["1.1.1.1"] || !ipSet["2.2.2.2"] {
		t.Errorf("banned IPs should contain 1.1.1.1 and 2.2.2.2, got %v", ips)
	}
}

func TestBanManager_Concurrent(t *testing.T) {
	bm := NewBanManager(100, 600, 3600, nil)
	var wg sync.WaitGroup

	const goroutines = 10
	const opsPerGoroutine = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := uint32(id)<<24 | uint32(j)
				bm.RegisterFailure(ip)
			}
		}(i)
	}

	wg.Wait()

	count := bm.GetBanCount()
	_ = bm.GetBannedIPs()
	_ = bm.IsBanned(uint32(1))
	if count == 0 {
		t.Log("Note: no bans triggered (threshold may not have been reached)")
	}
}

// ============================================
// Manager 集成测试
// ============================================

func TestNewManager(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Enabled:          true,
		SSHPort:          22,
		ShortConnSeconds: 2,
		MaxRetry:         5,
		FindTime:         600,
		BanDuration:      3600,
	}
	mgr := NewManager(cfg, newMockEBPFManager(), nil, nil)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.IsRunning() {
		t.Error("newly created manager should not be running")
	}
}

func TestManager_StopWithoutStart(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Enabled:          true,
		SSHPort:          22,
		MaxRetry:         5,
		FindTime:         600,
		BanDuration:      3600,
	}
	mgr := NewManager(cfg, newMockEBPFManager(), nil, nil)
	mgr.Stop() // 不应 panic
}

func TestManager_GetConfig(t *testing.T) {
	cfg := &config.FailGuardConfig{
		Enabled:     true,
		SSHPort:     2222,
		MaxRetry:    10,
		FindTime:    300,
		BanDuration: 7200,
	}
	mgr := NewManager(cfg, newMockEBPFManager(), nil, nil)
	gotCfg := mgr.GetConfig()

	if gotCfg["enabled"] != true {
		t.Error("enabled mismatch")
	}
	if gotCfg["max_retry"] != 10 {
		t.Errorf("max_retry = %v, want 10", gotCfg["max_retry"])
	}
	if gotCfg["find_time"] != 300 {
		t.Errorf("find_time = %v, want 300", gotCfg["find_time"])
	}
	if gotCfg["ban_duration"] != 7200 {
		t.Errorf("ban_duration = %v, want 7200", gotCfg["ban_duration"])
	}
}

// ============================================
// 辅助函数测试
// ============================================

func TestParseDurationNS(t *testing.T) {
	tests := []struct {
		seconds int
		wantNS  int64
	}{
		{1, 1000000000},
		{2, 2000000000},
		{60, 60000000000},
		{0, 0},
	}
	for _, tt := range tests {
		got := parseDurationNS(tt.seconds)
		var parsed int64
		_, err := fmt.Sscanf(got, "%d", &parsed)
		if err != nil {
			t.Errorf("parseDurationNS(%d) returned invalid number: %s", tt.seconds, got)
			continue
		}
		if parsed != tt.wantNS {
			t.Errorf("parseDurationNS(%d) = %s (parsed=%d), want %d ns", tt.seconds, got, parsed, tt.wantNS)
		}
	}
}

// IPv4 转换一致性测试
func TestFormatRoundTrip(t *testing.T) {
	testIPs := []string{
		"0.0.0.0",
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"255.255.255.255",
		"106.54.24.131",
		"1.2.3.4",
	}
	for _, ipStr := range testIPs {
		parsed := net.ParseIP(ipStr).To4()
		// 模拟真实 eBPF 数据流: IP 字符串 → 内存(网络字节序/大端) → binary.LittleEndian 反序列化
		raw := uint32(parsed[3])<<24 | uint32(parsed[2])<<16 | uint32(parsed[1])<<8 | uint32(parsed[0])
		roundTripped := FormatRemoteIP(raw)
		if roundTripped != ipStr {
			t.Errorf("roundtrip failed: %s → raw=%#08x → %s", ipStr, raw, roundTripped)
		}
	}
}
