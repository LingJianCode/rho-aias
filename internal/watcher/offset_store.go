// Package watcher 提供日志文件监听的共享工具，包括读取偏移量的持久化存储
package watcher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rho-aias/internal/logger"
)

// fileOffset 单个文件的偏移量与 inode 记录
type fileOffset struct {
	Inode  uint64 `json:"inode"`  // 文件 inode，用于检测日志轮转
	Offset int64  `json:"offset"` // 读取位置（字节偏移）
}

// OffsetStore 日志文件读取偏移量的持久化存储
// 将每个文件的 (inode, offset) 持久化到 JSON 文件，实现重启后从上次位置继续读取
type OffsetStore struct {
	mu       sync.Mutex
	filePath string             // 持久化 JSON 文件路径
	offsets  map[string]fileOffset // 文件路径 → 偏移量记录
}

// NewOffsetStore 创建偏移量存储
// stateFile: 持久化 JSON 文件的路径（如 ./data/waf_offset.json）
func NewOffsetStore(stateFile string) *OffsetStore {
	return &OffsetStore{
		filePath: stateFile,
		offsets:  make(map[string]fileOffset),
	}
}

// Load 从磁盘加载偏移量状态
// 如果文件不存在或格式错误则返回空状态（不会报错）
func (s *OffsetStore) Load() {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warnf("[OffsetStore] Failed to read state file %s: %v", s.filePath, err)
		}
		return
	}

	if len(data) == 0 {
		return
	}

	if err := json.Unmarshal(data, &s.offsets); err != nil {
		logger.Warnf("[OffsetStore] Failed to parse state file %s: %v", s.filePath, err)
		return
	}

	logger.Infof("[OffsetStore] Loaded %d file offset records from %s", len(s.offsets), s.filePath)
}

// GetOffset 获取指定文件的偏移量和 inode
// 返回 (offset, inode, ok)
func (s *OffsetStore) GetOffset(filePath string) (int64, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.offsets[filePath]
	if !ok {
		return 0, 0, false
	}
	return record.Offset, record.Inode, true
}

// SetOffset 更新指定文件的偏移量和 inode（仅更新内存）
// 磁盘持久化由 Save() 或 StartPeriodicSave() 负责
func (s *OffsetStore) SetOffset(filePath string, offset int64, inode uint64) {
	s.mu.Lock()
	s.offsets[filePath] = fileOffset{Inode: inode, Offset: offset}
	s.mu.Unlock()
}

// Save 保存当前状态到磁盘（持锁，线程安全）
func (s *OffsetStore) Save() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.save()
}

// StartPeriodicSave 启动定时保存，每隔 interval 保存一次偏移量到磁盘
// 返回一个 cancel 函数，调用后停止定时保存
func (s *OffsetStore) StartPeriodicSave(interval time.Duration) (cancel context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Save()
			}
		}
	}()
	return cancel
}

// save 实际写入磁盘（调用者需持有锁）
// 使用原子写入：先写临时文件，再 rename
func (s *OffsetStore) save() {
	if len(s.offsets) == 0 {
		return
	}

	// 确保目录存在
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Warnf("[OffsetStore] Failed to create directory %s: %v", dir, err)
		return
	}

	data, err := json.MarshalIndent(s.offsets, "", "  ")
	if err != nil {
		logger.Warnf("[OffsetStore] Failed to marshal state: %v", err)
		return
	}

	// 原子写入：先写临时文件
	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		logger.Warnf("[OffsetStore] Failed to write temp file %s: %v", tmpFile, err)
		return
	}

	// rename 为原子操作
	if err := os.Rename(tmpFile, s.filePath); err != nil {
		logger.Warnf("[OffsetStore] Failed to rename %s to %s: %v", tmpFile, s.filePath, err)
		return
	}
}
