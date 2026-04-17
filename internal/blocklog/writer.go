// Package blocklog 阻断日志模块
package blocklog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileWriter 按小时分割的日志文件写入器
type FileWriter struct {
	mu          sync.Mutex
	logDir      string        // 日志目录
	currentHour time.Time     // 当前小时
	currentFile *os.File      // 当前文件
	writer      *bufio.Writer // 缓冲写入器
	OnRotate    func(time.Time) // 整点轮转时的回调（由外部注入）
}

// NewFileWriter 创建新的文件写入器
func NewFileWriter(logDir string) (*FileWriter, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	fw := &FileWriter{
		logDir: logDir,
	}

	// 初始化第一个文件
	if err := fw.rotateFile(time.Now()); err != nil {
		return nil, err
	}

	return fw, nil
}

// Write 写入一条阻断记录
func (fw *FileWriter) Write(record BlockRecord) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 检查是否需要切换文件（按小时）
	now := time.Now()
	if fw.shouldRotate(now) {
		if err := fw.rotateFile(now); err != nil {
			return err
		}
	}

	// 序列化为 JSON Lines 格式
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	// 写入一行
	if _, err := fw.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write record: %w", err)
	}
	// 换行
	if _, err := fw.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	return nil
}

// Flush 刷新缓冲区到磁盘
func (fw *FileWriter) Flush() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.writer != nil {
		return fw.writer.Flush()
	}
	return nil
}

// Close 关闭文件写入器
func (fw *FileWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var err error
	if fw.writer != nil {
		if flushErr := fw.writer.Flush(); flushErr != nil {
			err = flushErr
		}
	}
	if fw.currentFile != nil {
		if closeErr := fw.currentFile.Close(); closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%w; close error: %v", err, closeErr)
			} else {
				err = closeErr
			}
		}
	}
	return err
}

// shouldRotate 检查是否需要切换文件
func (fw *FileWriter) shouldRotate(now time.Time) bool {
	// 获取当前小时的开始时间
	currentHourStart := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	return !fw.currentHour.Equal(currentHourStart)
}

// rotateFile 切换到新的日志文件
func (fw *FileWriter) rotateFile(now time.Time) error {
	// 触发轮转回调（在关闭旧文件前，让上层将当前小时的统计刷入 DB）
	if fw.OnRotate != nil {
		fw.OnRotate(now)
	}

	// 关闭旧文件
	if fw.writer != nil {
		if err := fw.writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush old file: %w", err)
		}
	}
	if fw.currentFile != nil {
		if err := fw.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close old file: %w", err)
		}
	}

	// 计算当前小时的开始时间
	currentHourStart := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	fw.currentHour = currentHourStart

	// 生成文件名: YYYY-MM-DD_HH.jsonl
	filename := fmt.Sprintf("%s_%02d.jsonl",
		now.Format("2006-01-02"),
		now.Hour(),
	)
	filePath := filepath.Join(fw.logDir, filename)

	// 打开或创建文件（追加模式）
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	fw.currentFile = file
	fw.writer = bufio.NewWriterSize(file, 4096) // 4KB 缓冲区

	return nil
}

// GetCurrentFilePath 获取当前日志文件路径
func (fw *FileWriter) GetCurrentFilePath() string {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.currentFile != nil {
		return fw.currentFile.Name()
	}
	return ""
}
