package source

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
