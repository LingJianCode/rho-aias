package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

const indexFile = "index.html"

type ServeFileSystem interface {
	http.FileSystem
	Exists(prefix string, path string) bool
}

type embedFileSystem struct {
	http.FileSystem
}

// Exists 检查指定路径是否存在且为**普通文件**
// 关键：对目录返回 false，避免 http.FileServer 对 "/" 触发 301 目录重定向
func (e embedFileSystem) Exists(_ string, p string) bool {
	f, err := e.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return false
	}

	// 只有普通文件才返回 true，目录放行给下游 NoRoute 处理
	return !stat.IsDir()
}

func EmbedFolder(embedFS fs.FS, targetPath string) ServeFileSystem {
	fsys, err := fs.Sub(embedFS, targetPath)
	if err != nil {
		panic(err)
	}
	return embedFileSystem{FileSystem: http.FS(fsys)}
}

// Serve 返回静态文件服务中间件（注册为 r.Use，不产生 Gin 路由）
func Serve(urlPrefix string, fs ServeFileSystem) gin.HandlerFunc {
	fileserver := http.FileServer(fs)
	if urlPrefix != "" {
		fileserver = http.StripPrefix(urlPrefix, fileserver)
	}
	return func(c *gin.Context) {
		if fs.Exists(urlPrefix, c.Request.URL.Path) {
			fileserver.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		}
	}
}

//go:embed dist/*
var distFS embed.FS

func RegisterFrontend(r *gin.Engine) {
	// 全局中间件：仅匹配真实存在的普通文件，目录自动放行
	r.Use(Serve("/", EmbedFolder(distFS, "dist")))

	// SPA fallback
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}
		data, err := fs.ReadFile(distFS, path.Join("dist", indexFile))
		if err != nil {
			c.String(http.StatusInternalServerError, "frontend not built: %v", err)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})
}
