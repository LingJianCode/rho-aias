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

	// 校验规则格式（IPv4、IPv6、CIDR、MAC）
	value := strings.TrimSpace(req.Value)
	if utils.ParseStringToIPType(value) == utils.IPTypeUnknown {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid rule format: must be a valid IPv4, IPv6, CIDR or MAC address",
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
