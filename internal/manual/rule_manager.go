package manual

import (
	"os"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"sort"
	"sync"
	"time"
)

// BlacklistManager 黑名单业务管理器（与 HTTP 无关）
// 协调 eBPF 规则操作、缓存持久化、白名单检查
type BlacklistManager struct {
	xdp     *ebpfs.Xdp
	cache   *Cache
	checker *WhitelistChecker
	mu      sync.Mutex // 保护缓存 read-modify-write 的原子性
}

// NewBlacklistManager 创建黑名单管理器
func NewBlacklistManager(xdp *ebpfs.Xdp, cache *Cache, checker *WhitelistChecker) *BlacklistManager {
	return &BlacklistManager{
		xdp:     xdp,
		cache:   cache,
		checker: checker,
	}
}

// Cache 返回缓存实例
func (m *BlacklistManager) Cache() *Cache { return m.cache }

// Checker 返回白名单检查器
func (m *BlacklistManager) Checker() *WhitelistChecker { return m.checker }

// AddRule 添加黑名单规则（eBPF + 缓存 + 白名单检查）
// 返回错误信息；当白名单冲突或规则已存在时返回具体错误
func (m *BlacklistManager) AddRule(value, remark string) error {
	// 白名单检查
	if m.checker != nil && m.checker.IsWhitelisted(value) {
		logger.Warnf("[Manual] IP/CIDR %s is in whitelist, refusing to add blacklist rule", value)
		return ErrWhitelistConflict
	}

	// 重复检查
	if m.cache != nil && m.cache.DataExists(CacheFileBlacklist) {
		if cacheData, err := m.cache.LoadData(CacheFileBlacklist); err == nil && cacheData.HasRule(value) {
			logger.Warnf("[Manual] IP/CIDR %s already exists in cache, skipping", value)
			return ErrRuleConflict
		}
	}

	// 1. 添加到 eBPF map
	if err := m.xdp.AddRule(value); err != nil {
		return err
	}

	// 2. 保存到缓存
	if m.cache != nil {
		if err := m.saveRuleToCache(value, remark); err != nil {
			logger.Warnf("[Manual] Failed to save rule to cache: %v", err)
		}
	}

	return nil
}

// DeleteRule 删除黑名单规则（eBPF + 缓存）
func (m *BlacklistManager) DeleteRule(value string) error {
	if err := m.xdp.DeleteRule(value); err != nil {
		return err
	}

	if m.cache != nil {
		if err := m.removeRuleFromCache(value); err != nil {
			logger.Warnf("[Manual] Failed to remove rule from cache: %v", err)
		}
	}

	return nil
}

// ListRules 列出所有黑名单规则（从缓存读取）
func (m *BlacklistManager) ListRules() ([]RuleEntry, error) {
	if m.cache == nil {
		return nil, nil
	}

	cacheData, err := m.cache.LoadData(CacheFileBlacklist)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	entries := make([]RuleEntry, 0, len(cacheData.Rules))
	for _, entry := range cacheData.Rules {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Value < entries[j].Value
	})

	return entries, nil
}

// saveRuleToCache 保存规则到缓存
func (m *BlacklistManager) saveRuleToCache(value, remark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cacheData *RuleCacheData
	if m.cache.DataExists(CacheFileBlacklist) {
		data, err := m.cache.LoadData(CacheFileBlacklist)
		if err != nil {
			cacheData = NewRuleCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = NewRuleCacheData()
	}

	cacheData.AddRule(*NewRuleEntryWithRemark(value, remark))
	return m.cache.SaveData(cacheData, CacheFileBlacklist)
}

// removeRuleFromCache 从缓存中删除规则
func (m *BlacklistManager) removeRuleFromCache(value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cache.DataExists(CacheFileBlacklist) {
		return nil
	}

	cacheData, err := m.cache.LoadData(CacheFileBlacklist)
	if err != nil {
		return err
	}

	cacheData.RemoveRule(value)

	if cacheData.RuleCount() == 0 {
		return m.cache.ClearData(CacheFileBlacklist)
	}

	return m.cache.SaveData(cacheData, CacheFileBlacklist)
}

// ============================================
// 白名单管理器
// ============================================

// WhitelistManager 白名单业务管理器（与 HTTP 无关）
type WhitelistManager struct {
	xdp     *ebpfs.Xdp
	cache   *Cache
	checker *WhitelistChecker
	mu      sync.Mutex
}

// NewWhitelistManager 创建白名单管理器
func NewWhitelistManager(xdp *ebpfs.Xdp, cache *Cache, checker *WhitelistChecker) *WhitelistManager {
	return &WhitelistManager{
		xdp:     xdp,
		cache:   cache,
		checker: checker,
	}
}

// Cache 返回缓存实例
func (m *WhitelistManager) Cache() *Cache { return m.cache }

// Checker 返回白名单检查器
func (m *WhitelistManager) Checker() *WhitelistChecker { return m.checker }

// AddRule 添加白名单规则（eBPF + 缓存 + 同步检查器）
func (m *WhitelistManager) AddRule(value, remark string) error {
	if err := m.xdp.AddWhitelistRule(value); err != nil {
		return err
	}

	if m.cache != nil {
		if err := m.saveRuleToCache(value, remark); err != nil {
			logger.Warnf("[Whitelist] Failed to save rule to cache: %v", err)
		}
	}

	if m.checker != nil {
		m.checker.Add(value)
	}

	return nil
}

// DeleteRule 删除白名单规则（eBPF + 缓存 + 同步检查器）
func (m *WhitelistManager) DeleteRule(value string) error {
	// 内置保护网段检查
	if IsProtectedNet(value) {
		return ErrProtectedNet
	}

	if err := m.xdp.DeleteWhitelistRule(value); err != nil {
		return err
	}

	if m.cache != nil {
		if err := m.removeRuleFromCache(value); err != nil {
			logger.Warnf("[Whitelist] Failed to remove rule from cache: %v", err)
		}
	}

	if m.checker != nil {
		m.checker.Remove(value)
	}

	return nil
}

// ListRules 列出所有白名单规则（合并内置保护网段 + 缓存用户规则）
func (m *WhitelistManager) ListRules() ([]WhitelistRuleEntry, error) {
	result := make([]WhitelistRuleEntry, 0)

	// 内置保护网段
	for _, ipNet := range ProtectedNets() {
		result = append(result, WhitelistRuleEntry{
			Value:     ipNet.String(),
			Remark:    "system",
			Protected: true,
		})
	}

	// 从缓存加载用户规则
	if m.cache != nil && m.cache.DataExists(CacheFileWhitelist) {
		cacheData, err := m.cache.LoadData(CacheFileWhitelist)
		if err != nil {
			sort.Slice(result, func(i, j int) bool {
				return result[i].Value < result[j].Value
			})
			return result, nil
		}

		for _, entry := range cacheData.Rules {
			result = append(result, WhitelistRuleEntry{
				Value:     entry.Value,
				Remark:    entry.Remark,
				AddedAt:   entry.AddedAt,
				Protected: false,
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Value < result[j].Value
	})

	return result, nil
}

// saveRuleToCache 保存白名单规则到缓存
func (m *WhitelistManager) saveRuleToCache(value, remark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cacheData *RuleCacheData
	if m.cache.DataExists(CacheFileWhitelist) {
		data, err := m.cache.LoadData(CacheFileWhitelist)
		if err != nil {
			cacheData = NewRuleCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = NewRuleCacheData()
	}

	cacheData.AddRule(*NewRuleEntryWithRemark(value, remark))
	return m.cache.SaveData(cacheData, CacheFileWhitelist)
}

// removeRuleFromCache 从缓存中删除白名单规则
func (m *WhitelistManager) removeRuleFromCache(value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cache.DataExists(CacheFileWhitelist) {
		return nil
	}

	cacheData, err := m.cache.LoadData(CacheFileWhitelist)
	if err != nil {
		return err
	}

	cacheData.RemoveRule(value)

	if cacheData.RuleCount() == 0 {
		return m.cache.ClearData(CacheFileWhitelist)
	}

	return m.cache.SaveData(cacheData, CacheFileWhitelist)
}

// WhitelistRuleEntry 白名单规则条目（含 Protected 标记）
type WhitelistRuleEntry struct {
	Value     string
	Remark    string
	AddedAt   time.Time
	Protected bool
}
