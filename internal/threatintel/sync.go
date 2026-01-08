// Package threatintel 威胁情报模块
package threatintel

import (
	"fmt"
	"log"
	"sync"

	"rho-aias/internal/ebpfs"
)

// Syncer 威胁情报原子同步器
// 负责将威胁情报数据安全地同步到内核 eBPF map，确保拦截不中断
type Syncer struct {
	xdp       *ebpfs.Xdp // XDP eBPF 程序接口
	batchSize int         // 批量操作大小
	mu        sync.Mutex // 互斥锁，保证并发安全
}

// NewSyncer 创建新的威胁情报同步器
// xdp: XDP eBPF 程序接口
// batchSize: 批量操作的大小限制
func NewSyncer(xdp *ebpfs.Xdp, batchSize int) *Syncer {
	return &Syncer{
		xdp:       xdp,
		batchSize: batchSize,
	}
}

// SyncToKernel 原子同步威胁情报到内核 eBPF map（增量更新）
// 通过计算当前规则与新数据的差异，实现无拦截空窗期的平滑更新
// sourceMask: 来源掩码，标识规则的来源
func (s *Syncer) SyncToKernel(data *IntelData, sourceMask uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 获取当前内核中的所有规则
	currentRules, err := s.xdp.GetRule()
	if err != nil {
		return fmt.Errorf("get current rules failed: %w", err)
	}

	// 2. 计算差异（需要新增和删除的规则）
	toAdd, toRemove := s.diff(currentRules, data, sourceMask)

	log.Printf("[Syncer] Current: %d, New: %d, ToAdd: %d, ToRemove: %d",
		len(currentRules), data.TotalCount(), len(toAdd), len(toRemove))

	// 3. 批量删除需要移除的规则
	if len(toRemove) > 0 {
		if err := s.batchDelete(toRemove); err != nil {
			return fmt.Errorf("batch delete failed: %w", err)
		}
		log.Printf("[Syncer] Removed %d rules", len(toRemove))
	}

	// 4. 批量添加需要新增的规则
	if len(toAdd) > 0 {
		if err := s.batchAdd(toAdd, sourceMask); err != nil {
			return fmt.Errorf("batch add failed: %w", err)
		}
		log.Printf("[Syncer] Added %d rules", len(toAdd))
	}

	return nil
}

// diff 计算当前规则和新威胁情报数据的差异
// 返回需要添加和需要删除的规则列表
// sourceMask: 来源掩码，用于判断规则是否仅由当前来源拥有
func (s *Syncer) diff(current []ebpfs.Rule, newData *IntelData, sourceMask uint32) (toAdd, toRemove []string) {
	// 构建当前规则的集合（仅包含当前来源的规则）
	currentSet := make(map[string]bool)
	for _, r := range current {
		// 只处理当前来源拥有的规则
		if r.Value.SourceMask&sourceMask != 0 {
			currentSet[r.Key] = true
		}
	}

	// 构建新数据的规则集合
	newSet := make(map[string]bool)
	for _, ip := range newData.IPv4Exact {
		newSet[ip] = true
	}
	for _, cidr := range newData.IPv4CIDR {
		newSet[cidr] = true
	}

	// 找出需要删除的规则（在当前内核中但不在新数据中）
	// 注意：只有当规则仅由当前来源拥有时才删除
	for k := range currentSet {
		if !newSet[k] {
			// 检查是否可以删除（仅当前来源拥有）
			shouldRemove := true
			for _, r := range current {
				if r.Key == k {
					// 如果规则有其他来源拥有，则只移除当前来源的位
					if r.Value.SourceMask&sourceMask != 0 && r.Value.SourceMask != sourceMask {
						shouldRemove = false
						// TODO: 这里需要实现按位删除的逻辑
						// 当前简化为不删除，等待完整的 bitmask 操作实现
						log.Printf("[Syncer] Rule %s owned by multiple sources (mask: 0x%x), skipping removal", k, r.Value.SourceMask)
					}
					break
				}
			}
			if shouldRemove {
				toRemove = append(toRemove, k)
			}
		}
	}

	// 找出需要添加的规则（在新数据中但不在当前内核中）
	for k := range newSet {
		if !currentSet[k] {
			toAdd = append(toAdd, k)
		}
	}

	return toAdd, toRemove
}

// batchAdd 批量添加规则到内核 eBPF map
func (s *Syncer) batchAdd(rules []string, sourceMask uint32) error {
	// 分批处理，避免单次操作过多导致超时
	for i := 0; i < len(rules); i += s.batchSize {
		end := i + s.batchSize
		if end > len(rules) {
			end = len(rules)
		}
		batch := rules[i:end]

		if err := s.xdp.BatchAddRules(batch, sourceMask); err != nil {
			return fmt.Errorf("batch add rules [%d:%d] failed: %w", i, end, err)
		}
	}
	return nil
}

// batchDelete 批量删除内核 eBPF map 中的规则
func (s *Syncer) batchDelete(rules []string) error {
	// 分批处理
	for i := 0; i < len(rules); i += s.batchSize {
		end := i + s.batchSize
		if end > len(rules) {
			end = len(rules)
		}
		batch := rules[i:end]

		if err := s.xdp.BatchDeleteRules(batch); err != nil {
			return fmt.Errorf("batch delete rules [%d:%d] failed: %w", i, end, err)
		}
	}
	return nil
}

// LoadAll 直接加载所有规则到内核（用于初始化）
// 跳过 GetRule() 和差异计算，直接批量添加
// 适用于：启动时从缓存加载，或确定需要覆盖所有规则的场景
func (s *Syncer) LoadAll(data *IntelData, sourceMask uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 构建完整的规则列表
	var toAdd []string
	toAdd = append(toAdd, data.IPv4Exact...)
	toAdd = append(toAdd, data.IPv4CIDR...)

	// 直接批量添加，跳过 GetRule() 和差异计算
	if len(toAdd) > 0 {
		if err := s.batchAdd(toAdd, sourceMask); err != nil {
			return fmt.Errorf("load all failed: %w", err)
		}
		log.Printf("[Syncer] Loaded %d rules from cache", len(toAdd))
	}

	return nil
}
