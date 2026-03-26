// Package blocklog 阻断日志模块
package blocklog

import (
	"sync"
	"time"

	"rho-aias/internal/logger"
)

const (
	// defaultBatchSize 批量写入阈值
	defaultBatchSize = 100
)

// Config 持久化配置
type Config struct {
	Enabled         bool          // 是否启用文件持久化
	LogDir          string        // 日志目录
	MemoryCacheSize int           // 内存缓存大小
	BufferSize      int           // 异步写入缓冲区大小
	FlushInterval   time.Duration // 刷盘间隔
}

// DefaultConfig 默认配置
var DefaultConfig = Config{
	Enabled:         true,
	LogDir:          "./logs/blocklog",
	MemoryCacheSize: 10000,
	BufferSize:      1000,
	FlushInterval:   5 * time.Second,
}

// AsyncWriter 异步日志写入器
type AsyncWriter struct {
	config    Config
	fileWriter *FileWriter
	recordCh  chan BlockRecord
	stopCh    chan struct{}
	wg        sync.WaitGroup
	stopped   bool
	stopMu    sync.RWMutex
}

// NewAsyncWriter 创建异步写入器
func NewAsyncWriter(config Config) (*AsyncWriter, error) {
	if !config.Enabled {
		return &AsyncWriter{
			config:  config,
			stopped: true,
		}, nil
	}

	// 创建文件写入器
	fileWriter, err := NewFileWriter(config.LogDir)
	if err != nil {
		return nil, err
	}

	aw := &AsyncWriter{
		config:     config,
		fileWriter: fileWriter,
		recordCh:   make(chan BlockRecord, config.BufferSize),
		stopCh:     make(chan struct{}),
	}

	// 启动后台写入协程
	aw.wg.Add(1)
	go aw.run()

	return aw, nil
}

// Write 异步写入一条记录
func (aw *AsyncWriter) Write(record BlockRecord) error {
	aw.stopMu.RLock()
	stopped := aw.stopped
	aw.stopMu.RUnlock()

	if stopped || !aw.config.Enabled {
		return nil
	}

	// 非阻塞写入，如果通道满了就丢弃
	select {
	case aw.recordCh <- record:
	default:
		// 通道满了，丢弃记录（避免阻塞）
		logger.Warnf("[BlockLog] Channel full (size=%d), dropping record: srcIP=%s, matchType=%s, timestamp=%d",
			cap(aw.recordCh), record.SrcIP, record.MatchType, record.Timestamp)
	}

	return nil
}

// Stop 停止异步写入器
func (aw *AsyncWriter) Stop() error {
	aw.stopMu.Lock()
	if aw.stopped {
		aw.stopMu.Unlock()
		return nil
	}
	aw.stopped = true
	aw.stopMu.Unlock()

	// 发送停止信号
	close(aw.stopCh)

	// 等待写入协程结束
	aw.wg.Wait()

	// 关闭文件写入器
	if aw.fileWriter != nil {
		return aw.fileWriter.Close()
	}

	return nil
}

// Flush 手动刷新缓冲区
func (aw *AsyncWriter) Flush() error {
	if aw.fileWriter != nil {
		return aw.fileWriter.Flush()
	}
	return nil
}

// run 后台写入协程
func (aw *AsyncWriter) run() {
	defer aw.wg.Done()

	ticker := time.NewTicker(aw.config.FlushInterval)
	defer ticker.Stop()

	var pendingRecords []BlockRecord

	for {
		select {
		case record := <-aw.recordCh:
			pendingRecords = append(pendingRecords, record)
			// 达到批量大小时立即写入
			if len(pendingRecords) >= defaultBatchSize {
				aw.writeBatch(pendingRecords)
				pendingRecords = pendingRecords[:0]
			}

		case <-ticker.C:
			// 定期刷新
			if len(pendingRecords) > 0 {
				aw.writeBatch(pendingRecords)
				pendingRecords = pendingRecords[:0]
			}
			aw.Flush()

		case <-aw.stopCh:
			// 停止信号，写入剩余记录
			if len(pendingRecords) > 0 {
				aw.writeBatch(pendingRecords)
			}
			aw.Flush()
			return
		}
	}
}

// writeBatch 批量写入记录
func (aw *AsyncWriter) writeBatch(records []BlockRecord) {
	if aw.fileWriter == nil {
		return
	}

	for _, record := range records {
		if err := aw.fileWriter.Write(record); err != nil {
			logger.Errorf("[BlockLog] Error writing record: %v", err)
		}
	}
}
