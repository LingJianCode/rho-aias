package handles

import (
	"os"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/internal/response"
	"rho-aias/utils"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rule struct {
	Value  string `json:"value"`
	Remark string `json:"remark"`
}

// BlocklistHandle 手动规则管理 API 处理器
type BlocklistHandle struct {
	xdp     *ebpfs.Xdp
	cache   *manual.Cache
	mu      sync.Mutex               // 保护缓存 read-modify-write 的原子性
	checker *manual.WhitelistChecker // 用户态白名单检查器（可选）
}

// NewBlocklistHandle 创建新的手动规则处理器
func NewBlocklistHandle(xdp *ebpfs.Xdp, cache *manual.Cache, checker *manual.WhitelistChecker) *BlocklistHandle {
	return &BlocklistHandle{
		xdp:     xdp,
		cache:   cache,
		checker: checker,
	}
}

// Cache 返回内部缓存实例
func (m *BlocklistHandle) Cache() *manual.Cache { return m.cache }

// Checker 返回内部白名单检查器
func (m *BlocklistHandle) Checker() *manual.WhitelistChecker { return m.checker }

// GetWhitelistChecker 返回内部白名单检查器
func (w *WhitelistHandle) GetWhitelistChecker() *manual.WhitelistChecker {
	return w.checker
}

// SetWhitelistChecker 设置白名单检查器（支持延迟注入）
func (m *BlocklistHandle) SetWhitelistChecker(checker *manual.WhitelistChecker) {
	m.checker = checker
}

// AddBlocklistRule 添加过滤规则
func (m *BlocklistHandle) AddBlocklistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	logger.Infof("[Manual] Add rule: %s", req.Value)

	// 校验规则格式（IPv4、CIDR）
	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown {
		response.BadRequest(c, "invalid rule format: must be a valid IPv4 or CIDR address")
		return
	}

	// 白名单检查：阻止封禁白名单中的 IP/CIDR
	if m.checker != nil && m.checker.IsWhitelisted(value) {
		logger.Warnf("[Manual] IP/CIDR %s is in whitelist, refusing to add blacklist rule", value)
		response.Conflict(c, response.CodeWhitelistConflict, "IP/CIDR is in whitelist, remove it from whitelist first")
		return
	}

	// 重复检查：阻止添加已在磁盘缓存中的规则
	if m.cache != nil && m.cache.DataExists(manual.CacheFileBlocklist) {
		if cacheData, err := m.cache.LoadData(manual.CacheFileBlocklist); err == nil && cacheData.HasRule(value) {
			logger.Warnf("[Manual] IP/CIDR %s already exists in cache, skipping", value)
			response.Conflict(c, response.CodeRuleConflict, "IP/CIDR already exists in blacklist")
			return
		}
	}

	//1. 添加到 eBPF map
	err := m.xdp.AddRule(value)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// 2. 保存到缓存（如果启用了持久化）
	if m.cache != nil {
		if err := m.saveRuleToCache(value, req.Remark); err != nil {
			logger.Warnf("[Manual] Failed to save rule to cache: %v", err)
			// 不影响 API 响应，因为 eBPF 已经添加成功
		}
	}

	response.OKMsg(c, "ok")
}

// DelBlocklistRule 删除过滤规则
func (m *BlocklistHandle) DelBlocklistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	logger.Infof("[Manual] Delete rule: %s", req.Value)

	//1. 从 eBPF map 删除
	err := m.xdp.DeleteRule(req.Value)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// 2. 从缓存删除（如果启用了持久化）
	if m.cache != nil {
		if err := m.removeRuleFromCache(req.Value); err != nil {
			logger.Warnf("[Manual] Failed to remove rule from cache: %v", err)
			// 不影响 API 响应，因为 eBPF 已经删除成功
		}
	}

	response.OKMsg(c, "ok")
}

// saveRuleToCache 保存规则到缓存
func (m *BlocklistHandle) saveRuleToCache(value, remark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 加载现有缓存
	var cacheData *manual.RuleCacheData
	if m.cache.DataExists(manual.CacheFileBlocklist) {
		data, err := m.cache.LoadData(manual.CacheFileBlocklist)
		if err != nil {
			// 如果加载失败，创建新的缓存数据
			cacheData = manual.NewRuleCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = manual.NewRuleCacheData()
	}

	// 添加规则
	cacheData.AddRule(*manual.NewRuleEntryWithRemark(value, remark))

	// 保存到文件
	return m.cache.SaveData(cacheData, manual.CacheFileBlocklist)
}

// removeRuleFromCache 从缓存中删除规则
func (m *BlocklistHandle) removeRuleFromCache(value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果缓存不存在，无需删除
	if !m.cache.DataExists(manual.CacheFileBlocklist) {
		return nil
	}

	// 加载现有缓存
	cacheData, err := m.cache.LoadData(manual.CacheFileBlocklist)
	if err != nil {
		return err
	}

	// 删除规则
	cacheData.RemoveRule(value)

	// 如果没有规则了，清空缓存文件
	if cacheData.RuleCount() == 0 {
		return m.cache.ClearData(manual.CacheFileBlocklist)
	}

	// 保存到文件
	return m.cache.SaveData(cacheData, manual.CacheFileBlocklist)
}

// ListBlocklistRules 查询手动黑名单规则列表（从磁盘缓存查询，避免遍历 eBPF map）
func (m *BlocklistHandle) ListBlocklistRules(c *gin.Context) {
	// 响应结构
	type ruleWithTime struct {
		Value   string `json:"value"`
		Remark  string `json:"remark"`
		AddedAt string `json:"added_at,omitempty"`
	}

	result := make([]ruleWithTime, 0)

	// 从磁盘缓存加载（直接 Load，避免 Exists+Load 竞态窗口）
	if m.cache != nil {
		cacheData, err := m.cache.LoadData(manual.CacheFileBlocklist)
		if err != nil {
			// 缓存文件不存在属正常（首次运行无规则），其他错误需记录
			if !os.IsNotExist(err) {
				logger.Warnf("[Manual] Failed to load cache: %v", err)
			}
			response.OK(c, gin.H{
				"rules": result,
				"total": 0,
			})
			return
		}

		for _, entry := range cacheData.Rules {
			result = append(result, ruleWithTime{
				Value:   entry.Value,
				Remark:  entry.Remark,
				AddedAt: entry.AddedAt.Format(time.RFC3339),
			})
		}
		// 排序保证输出顺序稳定（map 遍历随机）
		sort.Slice(result, func(i, j int) bool {
			return result[i].Value < result[j].Value
		})
	}

	response.OK(c, gin.H{
		"rules": result,
		"total": len(result),
	})
}

// ============================================
// 白名单管理 API 处理器
// ============================================

// WhitelistHandle 白名单管理 API 处理器
type WhitelistHandle struct {
	xdp   *ebpfs.Xdp
	cache *manual.Cache
	mu    sync.Mutex // 保护缓存 read-modify-write 的原子性

	// 用户态白名单检查器（可选），用于实时同步内存索引
	checker *manual.WhitelistChecker
}

// NewWhitelistHandle 创建新的白名单处理器
func NewWhitelistHandle(xdp *ebpfs.Xdp, cache *manual.Cache, checker *manual.WhitelistChecker) *WhitelistHandle {
	return &WhitelistHandle{
		xdp:     xdp,
		cache:   cache,
		checker: checker,
	}
}

// Cache 返回内部缓存实例
func (w *WhitelistHandle) Cache() *manual.Cache { return w.cache }

// Checker 返回内部白名单检查器
func (w *WhitelistHandle) Checker() *manual.WhitelistChecker { return w.checker }

// AddWhitelistRule 添加白名单规则
func (w *WhitelistHandle) AddWhitelistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	logger.Infof("[Whitelist] Add rule: %s", req.Value)

	// 校验规则格式（IPv4、CIDR）
	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown {
		response.BadRequest(c, "invalid whitelist rule format: must be a valid IPv4 or CIDR address")
		return
	}

	// 1. 添加到白名单 eBPF map
	err := w.xdp.AddWhitelistRule(value)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// 2. 保存到缓存（如果启用了持久化）
	if w.cache != nil {
		if err := w.saveWhitelistRuleToCache(value, req.Remark); err != nil {
			logger.Warnf("[Whitelist] Failed to save rule to cache: %v", err)
		}
	}

	// 3. 同步到用户态白名单检查器
	if w.checker != nil {
		w.checker.Add(value)
	}

	response.OKMsg(c, "ok")
}

// DelWhitelistRule 删除白名单规则
func (w *WhitelistHandle) DelWhitelistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	logger.Infof("[Whitelist] Delete rule: %s", req.Value)

	// 内置保护网段检查：禁止删除受保护的网段
	if manual.IsProtectedNet(req.Value) {
		logger.Warnf("[Whitelist] Refusing to delete protected net: %s", req.Value)
		response.Forbidden(c, "cannot delete built-in protected network segment")
		return
	}

	// 1. 从白名单 eBPF map 删除
	err := w.xdp.DeleteWhitelistRule(req.Value)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// 2. 从缓存删除（如果启用了持久化）
	if w.cache != nil {
		if err := w.removeWhitelistRuleFromCache(req.Value); err != nil {
			logger.Warnf("[Whitelist] Failed to remove rule from cache: %v", err)
		}
	}

	// 3. 从用户态白名单检查器中移除
	if w.checker != nil {
		w.checker.Remove(req.Value)
	}

	response.OKMsg(c, "ok")
}

// ListWhitelistRules 查询白名单规则列表（从磁盘缓存加载，合并内置保护网段）
func (w *WhitelistHandle) ListWhitelistRules(c *gin.Context) {
	type ruleWithTime struct {
		Value     string `json:"value"`
		Remark    string `json:"remark"`
		AddedAt   string `json:"added_at,omitempty"`
		Protected bool   `json:"protected"` // 是否为内置保护网段（不可删除）
	}

	result := make([]ruleWithTime, 0)

	// 添加内置保护网段
	for _, ipNet := range manual.ProtectedNets() {
		result = append(result, ruleWithTime{
			Value:     ipNet.String(),
			Remark:    "system",
			Protected: true,
		})
	}

	// 从磁盘缓存加载用户添加的规则
	if w.cache != nil && w.cache.DataExists(manual.CacheFileWhitelist) {
		cacheData, err := w.cache.LoadData(manual.CacheFileWhitelist)
		if err != nil {
			// 缓存加载失败，仍返回保护网段
			sort.Slice(result, func(i, j int) bool {
				return result[i].Value < result[j].Value
			})
			response.OK(c, gin.H{
				"rules": result,
				"total": len(result),
			})
			return
		}

		for _, entry := range cacheData.Rules {
			result = append(result, ruleWithTime{
				Value:     entry.Value,
				Remark:    entry.Remark,
				AddedAt:   entry.AddedAt.Format(time.RFC3339),
				Protected: false,
			})
		}
	}

	// 排序保证输出顺序稳定
	sort.Slice(result, func(i, j int) bool {
		return result[i].Value < result[j].Value
	})

	response.OK(c, gin.H{
		"rules": result,
		"total": len(result),
	})
}

// saveWhitelistRuleToCache 保存白名单规则到缓存
func (w *WhitelistHandle) saveWhitelistRuleToCache(value, remark string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var cacheData *manual.RuleCacheData
	if w.cache.DataExists(manual.CacheFileWhitelist) {
		data, err := w.cache.LoadData(manual.CacheFileWhitelist)
		if err != nil {
			cacheData = manual.NewRuleCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = manual.NewRuleCacheData()
	}

	cacheData.AddRule(*manual.NewRuleEntryWithRemark(value, remark))
	return w.cache.SaveData(cacheData, manual.CacheFileWhitelist)
}

// removeWhitelistRuleFromCache 从缓存中删除白名单规则
func (w *WhitelistHandle) removeWhitelistRuleFromCache(value string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.cache.DataExists(manual.CacheFileWhitelist) {
		return nil
	}

	cacheData, err := w.cache.LoadData(manual.CacheFileWhitelist)
	if err != nil {
		return err
	}

	cacheData.RemoveRule(value)

	if cacheData.RuleCount() == 0 {
		return w.cache.ClearData(manual.CacheFileWhitelist)
	}

	return w.cache.SaveData(cacheData, manual.CacheFileWhitelist)
}
