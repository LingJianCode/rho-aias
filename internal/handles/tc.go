package handles

import (
	"log"
	"net/http"
	"rho-aias/internal/ebpfs"

	"github.com/gin-gonic/gin"
)

// TcHandle handles TC rule API requests
type TcHandle struct {
	tc *ebpfs.Tc
}

// NewTcHandle creates a new TC handler
func NewTcHandle(tc *ebpfs.Tc) *TcHandle {
	return &TcHandle{tc: tc}
}

// tcRuleRequest represents a TC rule request
type tcRuleRequest struct {
	SrcIP   string `json:"src_ip" binding:"required"`
	DstPort uint16 `json:"dst_port" binding:"required"`
	Proto   string `json:"proto" binding:"required,oneof=tcp udp"`
}

// AddRule adds a TC filtering rule
func (h *TcHandle) AddRule(c *gin.Context) {
	var req tcRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}

	log.Printf("Adding TC rule: src_ip=%s, dst_port=%d, proto=%s", req.SrcIP, req.DstPort, req.Proto)

	err := h.tc.AddRule(req.SrcIP, req.DstPort, req.Proto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
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

// DeleteRule deletes a TC filtering rule
func (h *TcHandle) DeleteRule(c *gin.Context) {
	var req tcRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}

	log.Printf("Deleting TC rule: src_ip=%s, dst_port=%d, proto=%s", req.SrcIP, req.DstPort, req.Proto)

	err := h.tc.DeleteRule(req.SrcIP, req.DstPort, req.Proto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
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

// GetRules returns all TC filtering rules
func (h *TcHandle) GetRules(c *gin.Context) {
	rules, err := h.tc.GetRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data":    rules,
	})
}
