package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func init() {
	if _, err := fs.Stat(distContentFS, "index.html"); err != nil {
		panic("frontend: embedded dist/index.html not found, run 'npm run build' first")
	}
}

//go:embed all:dist
var distFS embed.FS

// distContentFS 剥离 "dist" 前级，使根路径直接指向 dist 内部文件
var distContentFS, _ = fs.Sub(distFS, "dist")

// RegisterFrontend 将前端静态文件注册到 Gin 路由
// 所有非 /api 开头的请求都会返回前端资源，支持 SPA history 模式
func RegisterFrontend(r *gin.Engine) {
	// 静态文件服务：/assets/xxx.js 等
	staticFiles, _ := fs.Sub(distContentFS, "assets")
	r.StaticFS("/assets", http.FS(staticFiles))

	// 根路径直接返回 index.html（避免 NoRoute 触发 301 目录重定向）
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.FileFromFS("index.html", http.FS(distContentFS))
	})

	// favicon 等根级静态文件
	r.GET("/favicon.svg", func(c *gin.Context) {
		c.FileFromFS("favicon.svg", http.FS(distContentFS))
	})

	// SPA fallback: 非 /api 开头的未匹配路由返回 index.html
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.FileFromFS("index.html", http.FS(distContentFS))
	})
}
