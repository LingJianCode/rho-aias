package handles

import (
	"net/http"

	"rho-aias/internal/ebpfs"

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
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 获取来源参数，默认为 "manual"
	source := c.Query("source")
	if source == "" {
		source = "manual"
	}

	// 如果 source 为 "all"，返回所有规则
	if source == "all" {
		c.JSON(http.StatusOK, gin.H{
			"message": "GetRules",
			"data": gin.H{
				"source": "all",
				"total":  len(res),
				"rules":  res,
			},
		})
		return
	}

	// 按来源筛选
	var filtered []ebpfs.Rule
	for _, r := range res {
		for _, s := range r.Sources {
			if s == source {
				filtered = append(filtered, r)
				break
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "GetRules",
		"data": gin.H{
			"source": source,
			"total":  len(filtered),
			"rules":  filtered,
		},
	})
}
