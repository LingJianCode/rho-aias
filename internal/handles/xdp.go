package handles

import (
	"log"
	"net/http"
	"rho-aias/internal/ebpfs"

	"github.com/gin-gonic/gin"
)

type XdpHandle struct {
	xdp *ebpfs.Xdp
}

func NewXdpHandle(xdp *ebpfs.Xdp) *XdpHandle {
	return &XdpHandle{xdp: xdp}
}

func (x *XdpHandle) AddRule(c *gin.Context) {
	var req rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}
	log.Println(req)
	err := x.xdp.AddRule(req.Value)
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

func (x *XdpHandle) GetRule(c *gin.Context) {
	res, err := x.xdp.GetRule()
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
