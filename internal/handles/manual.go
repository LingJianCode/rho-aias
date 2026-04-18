package handles

import (
	"rho-aias/internal/manual"
	"rho-aias/internal/response"
	"rho-aias/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type rule struct {
	Value  string `json:"value"`
	Remark string `json:"remark"`
}

// BlacklistHandle 手动规则管理 API 处理器
type BlacklistHandle struct {
	mgr *manual.BlacklistManager
}

// NewBlacklistHandle 创建新的手动规则处理器
func NewBlacklistHandle(mgr *manual.BlacklistManager) *BlacklistHandle {
	return &BlacklistHandle{
		mgr: mgr,
	}
}

// AddBlacklistRule 添加过滤规则
func (m *BlacklistHandle) AddBlacklistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown {
		response.BadRequest(c, "invalid rule format: must be a valid IPv4 or CIDR address")
		return
	}

	if err := m.mgr.AddRule(value, req.Remark); err != nil {
		switch err {
		case manual.ErrWhitelistConflict:
			response.Conflict(c, response.CodeWhitelistConflict, err.Error())
		case manual.ErrRuleConflict:
			response.Conflict(c, response.CodeRuleConflict, err.Error())
		default:
			response.InternalError(c, err.Error())
		}
		return
	}

	response.OKMsg(c, "ok")
}

// DelBlacklistRule 删除过滤规则
func (m *BlacklistHandle) DelBlacklistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if err := m.mgr.DeleteRule(req.Value); err != nil {
		response.InternalError(c, err.Error())
		return
	}

	response.OKMsg(c, "ok")
}

// ListBlacklistRules 查询手动黑名单规则列表（从磁盘缓存查询，避免遍历 eBPF map）
func (m *BlacklistHandle) ListBlacklistRules(c *gin.Context) {
	type ruleWithTime struct {
		Value   string `json:"value"`
		Remark  string `json:"remark"`
		AddedAt string `json:"added_at,omitempty"`
	}

	entries, err := m.mgr.ListRules()
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	result := make([]ruleWithTime, 0, len(entries))
	for _, entry := range entries {
		result = append(result, ruleWithTime{
			Value:   entry.Value,
			Remark:  entry.Remark,
			AddedAt: entry.AddedAt.Format(time.RFC3339),
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
	mgr *manual.WhitelistManager
}

// NewWhitelistHandle 创建新的白名单处理器
func NewWhitelistHandle(mgr *manual.WhitelistManager) *WhitelistHandle {
	return &WhitelistHandle{
		mgr: mgr,
	}
}

// AddWhitelistRule 添加白名单规则
func (w *WhitelistHandle) AddWhitelistRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	value := strings.TrimSpace(req.Value)
	ipType := utils.ParseStringToIPType(value)
	if ipType == utils.IPTypeUnknown {
		response.BadRequest(c, "invalid whitelist rule format: must be a valid IPv4 or CIDR address")
		return
	}

	if err := w.mgr.AddRule(value, req.Remark); err != nil {
		response.InternalError(c, err.Error())
		return
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

	if err := w.mgr.DeleteRule(req.Value); err != nil {
		switch err {
		case manual.ErrProtectedNet:
			response.Forbidden(c, err.Error())
		default:
			response.InternalError(c, err.Error())
		}
		return
	}

	response.OKMsg(c, "ok")
}

// ListWhitelistRules 查询白名单规则列表（从磁盘缓存加载，合并内置保护网段）
func (w *WhitelistHandle) ListWhitelistRules(c *gin.Context) {
	type ruleWithTime struct {
		Value     string `json:"value"`
		Remark    string `json:"remark"`
		AddedAt   string `json:"added_at,omitempty"`
		Protected bool   `json:"protected"`
	}

	entries, err := w.mgr.ListRules()
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	result := make([]ruleWithTime, 0, len(entries))
	for _, entry := range entries {
		r := ruleWithTime{
			Value:     entry.Value,
			Remark:    entry.Remark,
			Protected: entry.Protected,
		}
		if !entry.AddedAt.IsZero() {
			r.AddedAt = entry.AddedAt.Format(time.RFC3339)
		}
		result = append(result, r)
	}

	response.OK(c, gin.H{
		"rules": result,
		"total": len(result),
	})
}
