package manual

import (
	"testing"
)

func TestWhitelistChecker_Empty(t *testing.T) {
	wc := NewWhitelistChecker()

	if wc.IsWhitelisted("1.2.3.4") {
		t.Error("empty checker should not match any IP")
	}
}

// ============================================
// 内置保护网段测试（不可通过 API 移除）
// ============================================

func TestWhitelistChecker_ProtectedLoopback(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		match bool
	}{
		{"loopback classic", "127.0.0.1", true},
		{"loopback 127.0.0.2", "127.0.0.2", true},
		{"loopback 127.255.255.255", "127.255.255.255", true},
		{"loopback 127.0.0.0", "127.0.0.0", true},
		{"non-loopback 10.0.0.1", "10.0.0.1", false},
		{"non-loopback 1.2.3.4", "1.2.3.4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wc := NewWhitelistChecker()
			got := wc.IsWhitelisted(tt.ip)
			if got != tt.match {
				t.Errorf("IsWhitelisted(%q) = %v, want %v", tt.ip, got, tt.match)
			}
		})
	}
}

func TestWhitelistChecker_ProtectedCannotBeRemoved(t *testing.T) {
	wc := NewWhitelistChecker()

	// 127.0.0.1 应该被内置保护
	if !wc.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should be protected by default")
	}

	// 尝试通过 Remove 移除（不应生效）
	wc.Remove("127.0.0.0/8")
	if !wc.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should still be protected after Remove")
	}

	// LoadFromCache 也应不影响保护
	data := NewWhitelistCacheData()
	wc.LoadFromCache(data)
	if !wc.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should still be protected after LoadFromCache with empty data")
	}
}

func TestWhitelistChecker_ExactIPv4(t *testing.T) {
	wc := NewWhitelistChecker()
	data := NewWhitelistCacheData()
	data.AddWhitelistRule(*NewWhitelistRuleEntry("1.2.3.4"))
	data.AddWhitelistRule(*NewWhitelistRuleEntry("10.0.0.1"))
	wc.LoadFromCache(data)

	if !wc.IsWhitelisted("1.2.3.4") {
		t.Error("1.2.3.4 should be whitelisted")
	}
	if !wc.IsWhitelisted("10.0.0.1") {
		t.Error("10.0.0.1 should be whitelisted")
	}
	if wc.IsWhitelisted("5.6.7.8") {
		t.Error("5.6.7.8 should not be whitelisted")
	}
}

func TestWhitelistChecker_CIDR(t *testing.T) {
	wc := NewWhitelistChecker()
	data := NewWhitelistCacheData()
	data.AddWhitelistRule(*NewWhitelistRuleEntry("192.168.1.0/24"))
	wc.LoadFromCache(data)

	if !wc.IsWhitelisted("192.168.1.1") {
		t.Error("192.168.1.1 should match 192.168.1.0/24")
	}
	if !wc.IsWhitelisted("192.168.1.255") {
		t.Error("192.168.1.255 should match 192.168.1.0/24")
	}
	if !wc.IsWhitelisted("192.168.1.0") {
		t.Error("192.168.1.0 should match 192.168.1.0/24")
	}
	if wc.IsWhitelisted("192.168.2.1") {
		t.Error("192.168.2.1 should not match 192.168.1.0/24")
	}
	if wc.IsWhitelisted("10.0.0.1") {
		t.Error("10.0.0.1 should not match 192.168.1.0/24")
	}
}

func TestWhitelistChecker_MixedExactAndCIDR(t *testing.T) {
	wc := NewWhitelistChecker()
	data := NewWhitelistCacheData()
	data.AddWhitelistRule(*NewWhitelistRuleEntry("1.2.3.4"))
	data.AddWhitelistRule(*NewWhitelistRuleEntry("10.0.0.0/8"))
	wc.LoadFromCache(data)

	tests := []struct {
		ip     string
		expect bool
	}{
		{"1.2.3.4", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		got := wc.IsWhitelisted(tt.ip)
		if got != tt.expect {
			t.Errorf("IsWhitelisted(%q) = %v, want %v", tt.ip, got, tt.expect)
		}
	}
}

func TestWhitelistChecker_AddRemove(t *testing.T) {
	wc := NewWhitelistChecker()

	// Add
	wc.Add("1.2.3.4")
	if !wc.IsWhitelisted("1.2.3.4") {
		t.Error("1.2.3.4 should be whitelisted after Add")
	}

	// Add CIDR
	wc.Add("10.0.0.0/24")
	if !wc.IsWhitelisted("10.0.0.5") {
		t.Error("10.0.0.5 should match CIDR after Add")
	}

	// Remove exact IP
	wc.Remove("1.2.3.4")
	if wc.IsWhitelisted("1.2.3.4") {
		t.Error("1.2.3.4 should not be whitelisted after Remove")
	}
	// CIDR should still work
	if !wc.IsWhitelisted("10.0.0.5") {
		t.Error("10.0.0.5 should still match CIDR")
	}

	// Remove CIDR
	wc.Remove("10.0.0.0/24")
	if wc.IsWhitelisted("10.0.0.5") {
		t.Error("10.0.0.5 should not match CIDR after Remove")
	}
}

func TestWhitelistChecker_LoadFromCache_Nil(t *testing.T) {
	wc := NewWhitelistChecker()
	wc.Add("1.2.3.4")

	// nil data should not panic or clear existing data
	wc.LoadFromCache(nil)
	if !wc.IsWhitelisted("1.2.3.4") {
		t.Error("existing data should not be affected by nil LoadFromCache")
	}
}

func TestWhitelistChecker_LoadFromCache_ReplacesExisting(t *testing.T) {
	wc := NewWhitelistChecker()
	wc.Add("1.2.3.4")

	// Loading new cache should replace all existing data
	data := NewWhitelistCacheData()
	data.AddWhitelistRule(*NewWhitelistRuleEntry("5.6.7.8"))
	wc.LoadFromCache(data)

	if wc.IsWhitelisted("1.2.3.4") {
		t.Error("1.2.3.4 should not be whitelisted after LoadFromCache replaces data")
	}
	if !wc.IsWhitelisted("5.6.7.8") {
		t.Error("5.6.7.8 should be whitelisted after LoadFromCache")
	}
}
