package source

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache 通用的持久化缓存
// 使用 gob 二进制格式，采用原子写入策略（先写临时文件再 rename）
// 各模块通过泛型参数 [T] 传入自己的缓存数据类型
type Cache[T any] struct {
	dir      string // 缓存目录路径
	filename string // 缓存文件名（如 "intel_cache.bin"、"geoip_cache.bin"）
	mu       sync.RWMutex
}

// NewCache 创建新的缓存实例
// dir: 缓存文件存储目录
// filename: 缓存文件名
func NewCache[T any](dir, filename string) *Cache[T] {
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Warning: failed to create cache dir: %v\n", err)
	}
	return &Cache[T]{dir: dir, filename: filename}
}

// Save 保存缓存数据到本地磁盘（原子写入）
func (c *Cache[T]) Save(data T) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, c.filename)
	tmpPath := path + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create tmp file failed: %w", err)
	}

	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("encode cache data failed: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync cache data failed: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close tmp file failed: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename cache file failed: %w", err)
	}

	return nil
}

// Load 从本地磁盘加载缓存数据
func (c *Cache[T]) Load() (*T, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, c.filename)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file failed: %w", err)
	}
	defer f.Close()

	var data T
	decoder := gob.NewDecoder(f)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode cache data failed: %w", err)
	}

	return &data, nil
}

// Exists 检查缓存文件是否存在
func (c *Cache[T]) Exists() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, err := os.Stat(filepath.Join(c.dir, c.filename))
	return err == nil
}

// Clear 清除缓存文件
func (c *Cache[T]) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, c.filename)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cache file failed: %w", err)
	}
	return nil
}

// GetModTime 获取缓存文件的最后修改时间
func (c *Cache[T]) GetModTime() (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, err := os.Stat(filepath.Join(c.dir, c.filename))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}
