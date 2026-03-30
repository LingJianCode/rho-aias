package handles

import (
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
)

// RuleQueryHandle 规则查询处理器
type RuleQueryHandle struct {
	xdp *ebpfs.Xdp
}

// NewRuleQueryHandle 创建规则查询处理器
func NewRuleQueryHandle(xdp *ebpfs.Xdp) *RuleQueryHandle {
	return &RuleQueryHandle{
		xdp: xdp,
	}
}

// GetRules 获取规则列表
// source 参数: manual, ipsum, spamhaus, waf, ddos, all (默认: manual)
func (h *RuleQueryHandle) GetRules(c *gin.Context) {
	res, err := h.xdp.GetRule()
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	// 获取来源参数，默认为 "manual"
	source := c.Query("source")
	if source == "" {
		source = "manual"
	}

	// 校验 source 参数合法性
	validSources := map[string]bool{
		"manual": true, "ipsum": true, "spamhaus": true,
		"waf": true, "ddos": true, "rate_limit": true, "anomaly": true, "failguard": true, "all": true,
	}
	if !validSources[source] {
		response.BadRequest(c, "invalid source parameter, allowed values: manual, ipsum, spamhaus, waf, ddos, rate_limit, anomaly, failguard, all")
		return
	}

	// 如果 source 为 "all"，返回所有规则
	if source == "all" {
		response.OK(c, gin.H{
			"source": "all",
			"total":  len(res),
			"rules":  res,
		})
		return
	}

	// 按来源筛选（通过位掩码直接匹配，避免字符串遍历）
	sourceMask, ok := ebpfs.SourceStringToMask(source)
	if !ok {
		response.BadRequest(c, "invalid source parameter")
		return
	}
	var filtered []ebpfs.Rule
	for _, r := range res {
		if r.Value.SourceMask&sourceMask != 0 {
			filtered = append(filtered, r)
		}
	}
	response.OK(c, gin.H{
		"source": source,
		"total":  len(filtered),
		"rules":  filtered,
	})
}
