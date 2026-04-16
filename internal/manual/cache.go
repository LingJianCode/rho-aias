// Package manual 手动规则持久化模块
package manual

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"rho-aias/internal/logger"
	"sync"
	"time"
)

// Cache 手动规则持久化缓存
// 负责将手动添加的规则保存到本地磁盘，实现重启后恢复功能
type Cache struct {
	dir string       // 缓存目录路径
	mu  sync.RWMutex // 读写锁，保证并发安全
}

// NewCache 创建新的手动规则缓存
// dir: 缓存文件存储目录
func NewCache(dir string) *Cache {
	// 确保目录存在
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Warnf("[Manual] Warning: failed to create cache dir: %v\n", err)
	}
	return &Cache{
		dir: dir,
	}
}

// Save 保存手动规则缓存数据到本地磁盘（使用 gob 二进制格式）
// 采用原子写入策略：先写临时文件，再原子重命名，防止写入过程中断导致数据丢失
func (c *Cache) Save(data *CacheData) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "manual_cache.bin")
	tmpPath := path + ".tmp"

	// 1. 写入临时文件
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create tmp file failed: %w", err)
	}

	// 更新时间戳
	data.Timestamp = time.Now().Unix()

	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(data); err != nil {
		f.Close()          // 忽略关闭错误
		os.Remove(tmpPath) // 清理临时文件
		return fmt.Errorf("encode cache data failed: %w", err)
	}

	// 2. 确保数据写入磁盘
	if err := f.Sync(); err != nil {
		f.Close()          // 忽略关闭错误
		os.Remove(tmpPath) // 清理临时文件
		return fmt.Errorf("sync cache data failed: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close tmp file failed: %w", err)
	}

	// 3. 原子重命名
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename cache file failed: %w", err)
	}

	return nil
}

// Load 从本地磁盘加载手动规则缓存数据
func (c *Cache) Load() (*CacheData, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "manual_cache.bin")

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

	path := filepath.Join(c.dir, "manual_cache.bin")
	_, err := os.Stat(path)
	return err == nil
}

// Clear 清除缓存文件
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "manual_cache.bin")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cache file failed: %w", err)
	}
	return nil
}

// GetModTime 获取缓存文件的最后修改时间
func (c *Cache) GetModTime() (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "manual_cache.bin")
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// 初始化 gob 编码器，注册自定义类型
func init() {
	gob.Register(ManualRuleEntry{})
	gob.Register(CacheData{})
	gob.Register(WhitelistRuleEntry{})
	gob.Register(WhitelistCacheData{})
}

// ============================================
// 白名单持久化方法
// ============================================

// SaveWhitelist 保存白名单缓存数据到本地磁盘
// 采用原子写入策略：先写临时文件，再原子重命名
func (c *Cache) SaveWhitelist(data *WhitelistCacheData) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "whitelist_cache.bin")
	tmpPath := path + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create whitelist tmp file failed: %w", err)
	}

	data.Timestamp = time.Now().Unix()

	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("encode whitelist cache data failed: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync whitelist cache data failed: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close whitelist tmp file failed: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename whitelist cache file failed: %w", err)
	}

	return nil
}

// LoadWhitelist 从本地磁盘加载白名单缓存数据
func (c *Cache) LoadWhitelist() (*WhitelistCacheData, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "whitelist_cache.bin")

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open whitelist cache file failed: %w", err)
	}
	defer f.Close()

	var data WhitelistCacheData
	decoder := gob.NewDecoder(f)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode whitelist cache data failed: %w", err)
	}

	return &data, nil
}

// WhitelistExists 检查白名单缓存文件是否存在
func (c *Cache) WhitelistExists() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := filepath.Join(c.dir, "whitelist_cache.bin")
	_, err := os.Stat(path)
	return err == nil
}

// ClearWhitelist 清除白名单缓存文件
func (c *Cache) ClearWhitelist() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.dir, "whitelist_cache.bin")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove whitelist cache file failed: %w", err)
	}
	return nil
}
