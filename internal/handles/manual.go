package handles

import (
	"log"
	"net/http"
	"rho-aias/internal/ebpfs"

	"github.com/gin-gonic/gin"
)

// ManualHandle 手动规则管理 API 处理器
type ManualHandle struct {
	xdp *ebpfs.Xdp
}

// NewManualHandle 创建新的手动规则处理器
func NewManualHandle(xdp *ebpfs.Xdp) *ManualHandle {
	return &ManualHandle{xdp: xdp}
}

// AddRule 添加过滤规则
func (m *ManualHandle) AddRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}
	log.Println(req)
	err := m.xdp.AddRule(req.Value)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":    500,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
	})
}

// DelRule 删除过滤规则
func (m *ManualHandle) DelRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}
	log.Println(req)
	err := m.xdp.DeleteRule(req.Value)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":    500,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
	})
}

// GetRule 获取所有规则
func (m *ManualHandle) GetRule(c *gin.Context) {
	res, err := m.xdp.GetRule()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":    500,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "GetRule",
		"data":    res,
	})
}
