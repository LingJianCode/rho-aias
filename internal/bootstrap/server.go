package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/database"
	"rho-aias/internal/logger"

	"github.com/gin-gonic/gin"
)

// cancelFunc 是 context.CancelFunc 的类型别名，用于避免循环依赖
type cancelFunc = func()

// StartServer 启动 HTTP Server 并等待优雅退出信号
func StartServer(
	cfg *config.Config,
	r *gin.Engine,
	ctx context.Context,
	cancel cancelFunc,
	bizDB *database.Database,
) {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("[Server] Gin服务启动失败: %v", err)
		}
	}()
	logger.Infof("[Server] Gin服务已启动，监听端口: %d", cfg.Server.Port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	logger.Infof("[Main] 接收到信号: %v，开始优雅退出...", sig)

	cancel()
	logger.Info("[Main] 已取消所有后台 goroutine")

	if bizDB != nil {
		if err := bizDB.Close(); err != nil {
			logger.Warnf("[Main] Failed to close business database: %v", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("[Server] Gin服务优雅关闭失败: %v", err)
	}
	logger.Info("[Main] 服务已关闭")
	_ = logger.Sync()
}
