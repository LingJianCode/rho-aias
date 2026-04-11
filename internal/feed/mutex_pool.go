// Package feed 为威胁情报、地域封禁等数据馈送（Data Feed）模块提供公共基础设施，
// 包括泛型持久化缓存（Cache）、HTTP 数据获取器（Fetcher）、
// 并发互斥锁池（MutexPool）、数据源状态（SourceStatus）和数据库状态记录辅助函数。
//
// 各模块通过泛型参数 [T] 传入自己的数据类型，实现类型安全的复用。
package feed

import "sync"

// MutexPool 按键管理的互斥锁池
// 用于保证同一数据源不会并发执行更新操作
type MutexPool[K comparable] struct {
	mu    sync.Mutex
	locks map[K]*sync.Mutex
}

// NewMutexPool 创建新的互斥锁池
func NewMutexPool[K comparable]() *MutexPool[K] {
	return &MutexPool[K]{
		locks: make(map[K]*sync.Mutex),
	}
}

// Get 获取指定键的互斥锁（不存在则自动创建）
func (p *MutexPool[K]) Get(key K) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()

	mu, exists := p.locks[key]
	if !exists {
		mu = &sync.Mutex{}
		p.locks[key] = mu
	}
	return mu
}

// Remove 移除指定键的互斥锁（用于数据源动态删除场景，防止内存泄漏）
// 注意：调用前需确保该锁未被持有，否则可能引发竞态
func (p *MutexPool[K]) Remove(key K) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.locks, key)
}
