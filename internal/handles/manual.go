package handles

import (
	"net/http"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/utils"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

type rule struct {
	Value string
}

// ManualHandle 手动规则管理 API 处理器
type ManualHandle struct {
	xdp   *ebpfs.Xdp
	cache *manual.Cache
	mu    sync.Mutex // 保护缓存 read-modify-write 的原子性
}

// NewManualHandle 创建新的手动规则处理器
func NewManualHandle(xdp *ebpfs.Xdp, cache *manual.Cache) *ManualHandle {
	return &ManualHandle{
		xdp:   xdp,
		cache: cache,
	}
}

// AddRule 添加过滤规则
func (m *ManualHandle) AddRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "参数错误: " + err.Error(),
		})
		return
	}
	logger.Infof("[Manual] Add rule: %s", req.Value)

	// 校验规则格式（IPv4、IPv6、CIDR，不支持 MAC）
	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown || ipType == utils.IPTypeMAC {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid rule format: must be a valid IPv4, IPv6, or CIDR address (MAC not supported)",
		})
		return
	}

	//1. 添加到 eBPF map
	err := m.xdp.AddRule(value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 2. 保存到缓存（如果启用了持久化）
	if m.cache != nil {
		if err := m.saveRuleToCache(value); err != nil {
			logger.Warnf("[Manual] Failed to save rule to cache: %v", err)
			// 不影响 API 响应，因为 eBPF 已经添加成功
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}

// DelRule 删除过滤规则
func (m *ManualHandle) DelRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "参数错误: " + err.Error(),
		})
		return
	}
	logger.Infof("[Manual] Delete rule: %s", req.Value)

	//1. 从 eBPF map 删除
	err := m.xdp.DeleteRule(req.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 2. 从缓存删除（如果启用了持久化）
	if m.cache != nil {
		if err := m.removeRuleFromCache(req.Value); err != nil {
			logger.Warnf("[Manual] Failed to remove rule from cache: %v", err)
			// 不影响 API 响应，因为 eBPF 已经删除成功
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}

// saveRuleToCache 保存规则到缓存
func (m *ManualHandle) saveRuleToCache(value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 加载现有缓存
	var cacheData *manual.CacheData
	if m.cache.Exists() {
		data, err := m.cache.Load()
		if err != nil {
			// 如果加载失败，创建新的缓存数据
			cacheData = manual.NewCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = manual.NewCacheData()
	}

	// 添加规则
	cacheData.AddRule(*manual.NewManualRuleEntry(value))

	// 保存到文件
	return m.cache.Save(cacheData)
}

// removeRuleFromCache 从缓存中删除规则
func (m *ManualHandle) removeRuleFromCache(value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果缓存不存在，无需删除
	if !m.cache.Exists() {
		return nil
	}

	// 加载现有缓存
	cacheData, err := m.cache.Load()
	if err != nil {
		return err
	}

	// 删除规则
	cacheData.RemoveRule(value)

	// 如果没有规则了，清空缓存文件
	if cacheData.RuleCount() == 0 {
		return m.cache.Clear()
	}

	// 保存到文件
	return m.cache.Save(cacheData)
}

// ============================================
// 白名单管理 API 处理器
// ============================================

// WhitelistHandle 白名单管理 API 处理器
type WhitelistHandle struct {
	xdp   *ebpfs.Xdp
	cache *manual.Cache
	mu    sync.Mutex // 保护缓存 read-modify-write 的原子性
}

// NewWhitelistHandle 创建新的白名单处理器
func NewWhitelistHandle(xdp *ebpfs.Xdp, cache *manual.Cache) *WhitelistHandle {
	return &WhitelistHandle{
		xdp:   xdp,
		cache: cache,
	}
}

// AddWhitelistRule 添加白名单规则
func (w *WhitelistHandle) AddWhitelistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "参数错误: " + err.Error(),
		})
		return
	}
	logger.Infof("[Whitelist] Add rule: %s", req.Value)

	// 校验规则格式（IPv4、IPv6、CIDR，不支持 MAC）
	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown || ipType == utils.IPTypeMAC {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid whitelist rule format: must be a valid IPv4, IPv6 or CIDR address (MAC not supported)",
		})
		return
	}

	// 1. 添加到白名单 eBPF map
	err := w.xdp.AddWhitelistRule(value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 2. 保存到缓存（如果启用了持久化）
	if w.cache != nil {
		if err := w.saveWhitelistRuleToCache(value); err != nil {
			logger.Warnf("[Whitelist] Failed to save rule to cache: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}

// DelWhitelistRule 删除白名单规则
func (w *WhitelistHandle) DelWhitelistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "参数错误: " + err.Error(),
		})
		return
	}
	logger.Infof("[Whitelist] Delete rule: %s", req.Value)

	// 1. 从白名单 eBPF map 删除
	err := w.xdp.DeleteWhitelistRule(req.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 2. 从缓存删除（如果启用了持久化）
	if w.cache != nil {
		if err := w.removeWhitelistRuleFromCache(req.Value); err != nil {
			logger.Warnf("[Whitelist] Failed to remove rule from cache: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}

// ListWhitelistRules 查询白名单规则列表
func (w *WhitelistHandle) ListWhitelistRules(c *gin.Context) {
	rules, err := w.xdp.GetWhitelistRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 如果有缓存，补充 AddedAt 信息
	type ruleWithTime struct {
		Value   string `json:"value"`
		AddedAt string `json:"added_at,omitempty"`
	}

	result := make([]ruleWithTime, 0, len(rules))

	// 从缓存加载时间信息
	var cacheData *manual.WhitelistCacheData
	if w.cache != nil && w.cache.WhitelistExists() {
		cacheData, _ = w.cache.LoadWhitelist()
	}

	for _, rule := range rules {
		item := ruleWithTime{Value: rule}
		if cacheData != nil {
			if entry, ok := cacheData.Rules[rule]; ok {
				item.AddedAt = entry.AddedAt.Format("2006-01-02T15:04:05Z")
			}
		}
		result = append(result, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":  result,
		"total":  len(result),
	})
}

// saveWhitelistRuleToCache 保存白名单规则到缓存
func (w *WhitelistHandle) saveWhitelistRuleToCache(value string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var cacheData *manual.WhitelistCacheData
	if w.cache.WhitelistExists() {
		data, err := w.cache.LoadWhitelist()
		if err != nil {
			cacheData = manual.NewWhitelistCacheData()
		} else {
			cacheData = data
		}
	} else {
		cacheData = manual.NewWhitelistCacheData()
	}

	cacheData.AddWhitelistRule(*manual.NewWhitelistRuleEntry(value))
	return w.cache.SaveWhitelist(cacheData)
}

// removeWhitelistRuleFromCache 从缓存中删除白名单规则
func (w *WhitelistHandle) removeWhitelistRuleFromCache(value string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.cache.WhitelistExists() {
		return nil
	}

	cacheData, err := w.cache.LoadWhitelist()
	if err != nil {
		return err
	}

	cacheData.RemoveWhitelistRule(value)

	if cacheData.WhitelistRuleCount() == 0 {
		return w.cache.ClearWhitelist()
	}

	return w.cache.SaveWhitelist(cacheData)
}
