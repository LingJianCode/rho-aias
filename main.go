package main

import (
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/handles"
	"rho-aias/internal/routers"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize XDP (existing functionality)
	xdp := ebpfs.NewXdp("ens33")
	defer xdp.Close()
	err := xdp.Start()
	if err != nil {
		panic(err)
	}
	go xdp.MonitorEvents()
	xdpHandle := handles.NewXdpHandle(xdp)

	// Initialize TC (new functionality)
	tc := ebpfs.NewTc("ens33")
	defer tc.Close()
	err = tc.Start()
	if err != nil {
		panic(err)
	}
	tcHandle := handles.NewTcHandle(tc)

	// Setup router and routes
	router := gin.Default()
	api := router.Group("/api")

	// Register XDP routes (existing)
	routers.RegisterXdpRoutes(api, xdpHandle)

	// Register TC routes (new)
	routers.RegisterTcRoutes(api, tcHandle)

	router.Run(":8080")
}
