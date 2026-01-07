package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/handles"
	"rho-aias/internal/routers"
	"syscall"
	"time"

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
	r := gin.Default()
	api := r.Group("/api")

	// Register XDP routes (existing)
	routers.RegisterXdpRoutes(api, xdpHandle)

	// Register TC routes (new)
	routers.RegisterTcRoutes(api, tcHandle)

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gin服务启动失败: %v", err)
		}
	}()
	log.Println("Gin服务已启动，监听端口: 8080")

	// ----------优雅退出处理----------
	// 创建信号通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-quit
	log.Printf("接收到信号: %v，开始优雅退出...\n", sig)

	// ebpf由defer关闭
	// 优雅关闭Gin服务（设置超时时间，避免无限等待）
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Gin服务优雅关闭失败: %v", err)
	}
}
