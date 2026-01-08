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
	xdpHandle := handles.NewXdpHandle(xdp)

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

	// Setup router and routes
	r := gin.Default()
	api := r.Group("/api")

	// Register XDP routes (existing)
	routers.RegisterXdpRoutes(api, xdpHandle)

	// Register Intel routes (if enabled)
	if cfg.Intel.Enabled && intelMgr != nil {
		intelHandle := handles.NewIntelHandle(intelMgr)
		routers.RegisterIntelRoutes(api, intelHandle)
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
