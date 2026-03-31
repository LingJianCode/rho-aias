// Package logger 提供统一的日志管理功能
// 基于 uber-go/zap 实现，支持多级别日志输出、结构化日志、日志轮转和自动清理
package logger

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config 日志配置
type Config struct {
	Level         string `yaml:"level"`          // 日志级别: debug/info/warn/error
	Format        string `yaml:"format"`         // 输出格式: console/json
	OutputDir     string `yaml:"output_dir"`     // 日志目录
	MaxAgeDays    int    `yaml:"max_age_days"`   // 日志保留天数
	RotationHours int    `yaml:"rotation_hours"` // 按小时分割
}

// Logger 全局日志管理器
type Logger struct {
	config  *Config
	zap     *zap.Logger
	sugar   *zap.SugaredLogger
	writer  *lumberjack.Logger
	mu      sync.RWMutex
	stopped bool
	cron    *cron.Cron
}

var (
	globalLogger *Logger
	once         sync.Once
)

// Init 初始化全局日志管理器
func Init(cfg *Config) error {
	var initErr error
	once.Do(func() {
		globalLogger, initErr = NewLogger(cfg)
	})
	return initErr
}

// NewLogger 创建新的日志管理器
func NewLogger(cfg *Config) (*Logger, error) {
	// 设置默认值
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	if cfg.Format == "" {
		cfg.Format = "console"
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./logs"
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = 30
	}
	if cfg.RotationHours == 0 {
		cfg.RotationHours = 1
	}

	l := &Logger{
		config: cfg,
	}

	// 创建日志目录
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 创建核心组件
	core, writer, err := l.createCore()
	if err != nil {
		return nil, err
	}
	l.writer = writer

	// 创建 zap logger
	l.zap = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	l.sugar = l.zap.Sugar()

	// 初始化 Cron 定时任务
	l.cron = cron.New(cron.WithSeconds())

	// 添加定时清理任务（每 1 小时）
	l.cron.AddFunc("@every 1h", func() {
		l.cleanupOldLogs()
	})

	// 启动定时任务
	l.cron.Start()

	// 启动时先执行一次清理
	l.cleanupOldLogs()

	return l, nil
}

// createCore 创建 zapcore.Core
func (l *Logger) createCore() (zapcore.Core, *lumberjack.Logger, error) {
	// 解析日志级别
	level, err := l.parseLevel(l.config.Level)
	if err != nil {
		return nil, nil, err
	}

	// 创建编码器
	encoder := l.createEncoder(l.config.Format)

	// 创建文件写入器
	writer := &lumberjack.Logger{
		Filename:   filepath.Join(l.config.OutputDir, "app.log"),
		MaxSize:    0, // 不按大小分割
		MaxBackups: 0, // 不限制备份数量（使用自定义清理）
		MaxAge:     l.config.MaxAgeDays,
		Compress:   false,
		LocalTime:  true,
	}

	// 创建多路输出（控制台 + 文件）
	consoleEncoder := l.createEncoder("console")
	consoleWriter := zapcore.AddSync(os.Stdout)

	// 文件输出使用 JSON 格式，控制台使用 Console 格式
	fileWriter := zapcore.AddSync(writer)

	// 如果配置为 console 格式，文件也使用 console；否则文件使用 JSON
	fileEncoder := encoder
	if l.config.Format == "json" {
		fileEncoder = l.createEncoder("json")
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleWriter, level),
		zapcore.NewCore(fileEncoder, fileWriter, level),
	)

	return core, writer, nil
}

// parseLevel 解析日志级别字符串
func (l *Logger) parseLevel(levelStr string) (zapcore.Level, error) {
	switch strings.ToLower(levelStr) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "dpanic":
		return zapcore.DPanicLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level: %s", levelStr)
	}
}

// createEncoder 创建编码器
func (l *Logger) createEncoder(format string) zapcore.Encoder {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000"),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if format == "json" {
		return zapcore.NewJSONEncoder(encoderConfig)
	}

	// console 格式
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// cleanupOldLogs 清理过期日志
func (l *Logger) cleanupOldLogs() {
	if l.config.MaxAgeDays <= 0 {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.config.MaxAgeDays)

	// 遍历日志目录
	entries, err := os.ReadDir(l.config.OutputDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// 检查文件修改时间
		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(l.config.OutputDir, entry.Name())
			os.Remove(filePath)
		}
	}
}

// Sync 刷新日志缓冲区
func (l *Logger) Sync() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.zap != nil {
		return l.zap.Sync()
	}
	return nil
}

// Close 关闭日志管理器
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.stopped = true

	// 停止 Cron 定时任务
	if l.cron != nil {
		l.cron.Stop()
	}

	if l.writer != nil {
		l.writer.Close()
	}
	if l.zap != nil {
		return l.zap.Sync()
	}
	return nil
}

// ========== 全局日志函数 ==========

// Debug 输出 Debug 级别日志
func Debug(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Debug(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Info 输出 Info 级别日志
func Info(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Info(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Warn 输出 Warn 级别日志
func Warn(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Warn(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Error 输出 Error 级别日志
func Error(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Error(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Fatal 输出 Fatal 级别日志并退出程序
func Fatal(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Fatal(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Panic 输出 Panic 级别日志
func Panic(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.zap != nil {
			globalLogger.zap.Panic(msg, fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Debugf 格式化输出 Debug 级别日志
func Debugf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Debugf(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Infof 格式化输出 Info 级别日志
func Infof(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Infof(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Warnf 格式化输出 Warn 级别日志
func Warnf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Warnf(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Errorf 格式化输出 Error 级别日志
func Errorf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Errorf(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Fatalf 格式化输出 Fatal 级别日志并退出程序
func Fatalf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Fatalf(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Panicf 格式化输出 Panic 级别日志
func Panicf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.mu.RLock()
		if !globalLogger.stopped && globalLogger.sugar != nil {
			globalLogger.sugar.Panicf(template, args...)
		}
		globalLogger.mu.RUnlock()
	}
}

// Sync 刷新全局日志缓冲区
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// Close 关闭全局日志管理器
func Close() error {
	if globalLogger != nil {
		return globalLogger.Close()
	}
	return nil
}

// ========== Gin 中间件 ==========

// GinLogger Gin 日志中间件
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if globalLogger == nil || globalLogger.sugar == nil {
			c.Next()
			return
		}

		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)

		globalLogger.mu.RLock()
		if globalLogger.stopped || globalLogger.sugar == nil {
			globalLogger.mu.RUnlock()
			return
		}

		fields := []interface{}{
			"status", c.Writer.Status(),
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"ip", c.ClientIP(),
			"latency", latency.String(),
			"user-agent", c.Request.UserAgent(),
		}

		if len(c.Errors) > 0 {
			fields = append(fields, "errors", c.Errors.String())
		}

		switch {
		case c.Writer.Status() >= http.StatusInternalServerError:
			globalLogger.sugar.Errorw("[GIN]", fields...)
		case c.Writer.Status() >= http.StatusBadRequest:
			globalLogger.sugar.Warnw("[GIN]", fields...)
		default:
			globalLogger.sugar.Infow("[GIN]", fields...)
		}
		globalLogger.mu.RUnlock()
	}
}

// GinRecovery Gin 异常恢复中间件
func GinRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				if globalLogger != nil && globalLogger.sugar != nil {
					globalLogger.mu.RLock()
					if !globalLogger.stopped && globalLogger.sugar != nil {
						globalLogger.sugar.Errorw("[GIN] Panic recovered",
							"error", err,
							"path", c.Request.URL.Path,
							"method", c.Request.Method,
							"stack", string(debug.Stack()),
						)
					}
					globalLogger.mu.RUnlock()
				}
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}
