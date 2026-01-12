package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/handles"
	"rho-aias/internal/routers"
	"rho-aias/internal/threatintel"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.NewConfig("config.yml")
	log.Println(cfg)
	// Initialize XDP (existing functionality)
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)
	defer xdp.Close()
	err := xdp.Start()
	if err != nil {
		panic(err)
	}
	go xdp.MonitorEvents()
	manualHandle := handles.NewManualHandle(xdp)

	// Initialize Intel Manager (if enabled)
	var intelMgr *threatintel.Manager
	if cfg.Intel.Enabled {
		intelMgr = threatintel.NewManager(&cfg.Intel, xdp)
		if err := intelMgr.Start(); err != nil {
			log.Printf("Warning: Intel manager start failed: %v", err)
		}
		log.Println("[Main] Intelligence module initialized")
		defer intelMgr.Stop()
	}

	// Initialize Geo-Blocking Manager (if enabled)
	var geoMgr *geoblocking.Manager
	if cfg.GeoBlocking.Enabled {
		geoMgr = geoblocking.NewManager(&cfg.GeoBlocking, xdp)
		if err := geoMgr.Start(); err != nil {
			log.Printf("Warning: Geo-blocking manager start failed: %v", err)
		}
		log.Println("[Main] Geo-blocking module initialized")
		defer geoMgr.Stop()
	}

	// Setup router and routes
	r := gin.Default()
	api := r.Group("/api")

	// Register Manual routes (existing)
	routers.RegisterManualRoutes(api, manualHandle)

	// Register Intel routes (if enabled)
	if cfg.Intel.Enabled && intelMgr != nil {
		intelHandle := handles.NewIntelHandle(intelMgr)
		routers.RegisterIntelRoutes(api, intelHandle)
	}

	// Register Geo-Blocking routes (if enabled)
	if cfg.GeoBlocking.Enabled && geoMgr != nil {
		geoHandle := handles.NewGeoBlockingHandle(geoMgr)
		routers.RegisterGeoBlockingRoutes(api, geoHandle)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gin服务启动失败: %v", err)
		}
	}()
	log.Printf("Gin服务已启动，监听端口: %d\n", cfg.Server.Port)

	// ----------优雅退出处理----------
	// 创建信号通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-quit
	log.Printf("接收到信号: %v，开始优雅退出...\n", sig)

	// 停止情报管理器

	// ebpf由defer关闭
	// 优雅关闭Gin服务（设置超时时间，避免无限等待）
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Gin服务优雅关闭失败: %v", err)
	}
}
