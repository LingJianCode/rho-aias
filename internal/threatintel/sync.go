// Package threatintel 威胁情报模块
package threatintel

import (
	"fmt"
	"sync"

	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
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

	// 2. 计算差异（需要新增、删除和更新掩码的规则）
	toAdd, toRemove, toUpdateMask := s.diff(currentRules, data, sourceMask)

	logger.Infof("[Syncer] Current: %d, New: %d, ToAdd: %d, ToRemove: %d, ToUpdateMask: %d",
		len(currentRules), data.TotalCount(), len(toAdd), len(toRemove), len(toUpdateMask))

	// 3. 批量删除需要移除的规则（仅单源拥有）
	if len(toRemove) > 0 {
		if err := s.batchDelete(toRemove); err != nil {
			return fmt.Errorf("batch delete failed: %w", err)
		}
		logger.Infof("[Syncer] Removed %d rules", len(toRemove))
	}

	// 4. 批量更新掩码（多源共有规则，按位删除当前来源）
	if len(toUpdateMask) > 0 {
		if _, err := s.xdp.BatchUpdateRuleSourceMask(toUpdateMask, sourceMask); err != nil {
			return fmt.Errorf("batch update mask failed: %w", err)
		}
		logger.Infof("[Syncer] Updated mask for %d rules (removed source 0x%x)", len(toUpdateMask), sourceMask)
	}

	// 5. 批量添加需要新增的规则
	if len(toAdd) > 0 {
		if err := s.batchAdd(toAdd, sourceMask); err != nil {
			return fmt.Errorf("batch add failed: %w", err)
		}
		logger.Infof("[Syncer] Added %d rules", len(toAdd))
	}

	return nil
}

// diff 计算当前规则和新威胁情报数据的差异
// 返回需要添加、需要删除和需要更新掩码的规则列表
// sourceMask: 来源掩码，用于判断规则是否仅由当前来源拥有
func (s *Syncer) diff(current []ebpfs.Rule, newData *IntelData, sourceMask uint32) (toAdd, toRemove, toUpdateMask []string) {
	// 构建当前规则的集合（仅包含当前来源的规则）
	// 同时构建规则键到完整规则信息的映射，避免后续双重循环
	currentSet := make(map[string]bool)
	currentRuleMap := make(map[string]ebpfs.Rule)
	for _, r := range current {
		// 只处理当前来源拥有的规则
		if r.Value.SourceMask&sourceMask != 0 {
			currentSet[r.Key] = true
			currentRuleMap[r.Key] = r
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

	// 找出需要删除或更新掩码的规则（在当前内核中但不在新数据中）
	// 优化：使用 map 查找替代双重循环，O(n+m) 替代 O(n*m)
	for k := range currentSet {
		if !newSet[k] {
			// 使用 map 查找规则的完整信息，避免双重循环
			if r, ok := currentRuleMap[k]; ok {
				// 检查是否可以删除（仅当前来源拥有）
				if r.Value.SourceMask == sourceMask {
					// 只有当前来源拥有，直接删除
					toRemove = append(toRemove, k)
				} else if r.Value.SourceMask&sourceMask != 0 {
					// 多源共有规则，按位删除当前来源
					toUpdateMask = append(toUpdateMask, k)
					logger.Debugf("[Syncer] Rule %s owned by multiple sources (mask: 0x%x), will remove source bit 0x%x",
						k, r.Value.SourceMask, sourceMask)
				}
			}
		}
	}

	// 找出需要添加的规则（在新数据中但不在当前内核中）
	for k := range newSet {
		if !currentSet[k] {
			toAdd = append(toAdd, k)
		}
	}

	return toAdd, toRemove, toUpdateMask
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
		logger.Infof("[Syncer] Loaded %d rules from cache", len(toAdd))
	}

	return nil
}

// RemoveBySourceMask 按来源掩码从内核 eBPF map 中移除规则
// 用于数据源禁用时立即清理该源的所有恶意 IP
func (s *Syncer) RemoveBySourceMask(sourceMask uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 获取当前内核中的所有规则
	currentRules, err := s.xdp.GetRule()
	if err != nil {
		return fmt.Errorf("get current rules failed: %w", err)
	}

	// 2. 分类：仅该源拥有的（直接删除）vs 多源共有的（更新掩码）
	var toRemove []string
	var toUpdateMask []string

	for _, r := range currentRules {
		if r.Value.SourceMask&sourceMask == 0 {
			continue // 不属于该源，跳过
		}
		if r.Value.SourceMask == sourceMask {
			// 仅当前源拥有，直接删除
			toRemove = append(toRemove, r.Key)
		} else {
			// 多源共有，按位移除当前源
			toUpdateMask = append(toUpdateMask, r.Key)
		}
	}

	// 3. 执行批量操作
	if len(toRemove) > 0 {
		if err := s.batchDelete(toRemove); err != nil {
			return fmt.Errorf("batch delete failed: %w", err)
		}
		logger.Infof("[Syncer] Removed %d rules (source mask 0x%x)", len(toRemove), sourceMask)
	}

	if len(toUpdateMask) > 0 {
		if _, err := s.xdp.BatchUpdateRuleSourceMask(toUpdateMask, sourceMask); err != nil {
			return fmt.Errorf("batch update mask failed: %w", err)
		}
		logger.Infof("[Syncer] Updated mask for %d rules (removed source 0x%x)", len(toUpdateMask), sourceMask)
	}

	totalCleaned := len(toRemove) + len(toUpdateMask)
	if totalCleaned > 0 {
		logger.Infof("[Syncer] Cleanup done: removed=%d, updated_mask=%d, total=%d",
			len(toRemove), len(toUpdateMask), totalCleaned)
	} else {
		logger.Infof("[Syncer] No rules found for source mask 0x%x, nothing to clean", sourceMask)
	}

	return nil
}
