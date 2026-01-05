package handles

import (
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
	c.JSON(http.StatusOK, gin.H{
		"message": "AddRule",
	})
}

func (x *XdpHandle) GetRule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "GetRule",
	})
}
