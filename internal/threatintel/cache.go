// Package threatintel 威胁情报模块
package threatintel

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache 威胁情报持久化缓存
// 负责将威胁情报数据保存到本地磁盘，实现离线启动功能
type Cache struct {
	dir string     // 缓存目录路径
	mu  sync.RWMutex // 读写锁，保证并发安全
}

// NewCache 创建新的威胁情报缓存
// dir: 缓存文件存储目录
func NewCache(dir string) *Cache {
	// 确保目录存在
	if err := os.MkdirAll(dir, 0755); err != nil {
		// 如果创建失败，继续使用，保存时会报错
		fmt.Printf("Warning: failed to create cache dir: %v\n", err)
	}
	return &Cache{
		dir: dir,
	}
}

// Save 保存威胁情报缓存数据到本地磁盘（使用 gob 二进制格式）
func (c *Cache) Save(data *CacheData) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "intel_cache.bin")

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create cache file failed: %w", err)
	}
	defer f.Close()

	// 更新时间戳
	data.Timestamp = time.Now().Unix()

	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("encode cache data failed: %w", err)
	}

	return nil
}

// Load 从本地磁盘加载威胁情报缓存数据
func (c *Cache) Load() (*CacheData, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "intel_cache.bin")

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file failed: %w", err)
	}
	defer f.Close()

	var data CacheData
	decoder := gob.NewDecoder(f)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode cache data failed: %w", err)
	}

	return &data, nil
}

// Exists 检查缓存文件是否存在
func (c *Cache) Exists() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "intel_cache.bin")
	_, err := os.Stat(path)
	return err == nil
}

// Clear 清除缓存文件
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "intel_cache.bin")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cache file failed: %w", err)
	}
	return nil
}

// GetModTime 获取缓存文件的最后修改时间
func (c *Cache) GetModTime() (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "intel_cache.bin")
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// 初始化 gob 编码器，注册自定义类型
func init() {
	gob.Register(SourceID(""))
	gob.Register(IntelData{})
	gob.Register(CacheData{})
}
