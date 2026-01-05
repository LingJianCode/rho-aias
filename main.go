package main

import (
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/handles"
	"rho-aias/internal/routers"

	"github.com/gin-gonic/gin"
)

func main() {
	xdp := ebpfs.NewXdp("ens33")
	xdpHandle := handles.NewXdpHandle(xdp)
	router := gin.Default()
	api := router.Group("/api")
	routers.RegisterXdpRoutes(api, xdpHandle)

	router.Run(":8080")
}
