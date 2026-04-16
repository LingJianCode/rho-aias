package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed dist/*
var distFS embed.FS

func init() {
	if _, err := fs.Stat(distFS, "index.html"); err != nil {
		panic("frontend: embedded dist/index.html not found, run 'npm run build' first")
	}
}

// RegisterFrontend 将前端静态文件注册到 Gin 路由
// 所有非 /api 开头的请求都会返回前端资源，支持 SPA history 模式
func RegisterFrontend(r *gin.Engine) {
	// 静态文件服务：所有 /xxx 路径优先匹配嵌入的文件（index.html、assets/、favicon.svg 等）
	r.StaticFS("/", http.FS(distFS))

	// SPA fallback：未命中静态文件的非 API 请求返回 index.html
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}
		c.FileFromFS("index.html", http.FS(distFS))
	})
}
