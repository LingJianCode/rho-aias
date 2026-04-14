package ebpfs

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"rho-aias/internal/logger"
	"rho-aias/utils"
)

// ============================================
// 规则管理：精确/CIDR 黑名单 CRUD + 批量操作
// ============================================

// lookupExistingValue 根据 IP 类型构造 key 并从对应的 eBPF map 中查找现有值
// 调用者必须已持有 mapMu 锁
func (x *Xdp) lookupExistingValue(iptype utils.IPType, rawBytes []byte) (BlockValue, bool) {
	if x.objects == nil {
		return BlockValue{}, false
	}
	var blockValue BlockValue
	switch iptype {
	case utils.IPTypeIPv4:
		var key [4]byte
		copy(key[:], rawBytes)
		if x.objects.BlockIpv4List.Lookup(&key, &blockValue) == nil {
			return blockValue, true
		}
	case utils.IPTypeIPV4CIDR:
		var key IPv4TrieKey
		copy(key.Addr[:], rawBytes[4:])
		key.PrefixLen = binary.LittleEndian.Uint32(rawBytes[:4])
		if x.objects.BlockIpv4CidrTrie.Lookup(&key, &blockValue) == nil {
			return blockValue, true
		}
	}
	return BlockValue{}, false
}

// updateMap 更新内核 map - 支持来源掩码
func (x *Xdp) updateMap(iptype utils.IPType, value []byte, blockValue BlockValue, add bool) (err error) {
	if x.objects == nil {
		return fmt.Errorf("eBPF not initialized")
	}
	switch iptype {
	case utils.IPTypeIPv4:
		if add {
			err = x.objects.BlockIpv4List.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv4List.Delete(value)
		}
	case utils.IPTypeIPV4CIDR:
		if add {
			err = x.objects.BlockIpv4CidrTrie.Put(value, blockValue)
		} else {
			err = x.objects.BlockIpv4CidrTrie.Delete(value)
		}
	default:
		return fmt.Errorf("unsupported match type: %v", iptype)
	}
	return err
}

// AddRule 添加手动规则（设置 MANUAL 位）
func (x *Xdp) AddRule(value string) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	logger.Debugf("[XDP] AddRule: bytes=%v, iptype=%v", bytes, iptype)

	currentValue, exists := x.lookupExistingValue(iptype, bytes)

	var blockValue BlockValue
	if exists {
		newMask := currentValue.SourceMask | SourceMaskManual
		blockValue = NewBlockValueWithPreserve(newMask, currentValue.Priority, currentValue.Expiry)
	} else {
		blockValue = NewBlockValue(SourceMaskManual)
	}

	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// DeleteRule 删除规则（完全删除，不论来源）
func (x *Xdp) DeleteRule(value string) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	err = x.updateMap(iptype, bytes, BlockValue{}, false)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// AddRuleWithSource 添加指定来源的规则
func (x *Xdp) AddRuleWithSource(value string, sourceMask uint32) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}

	currentValue, exists := x.lookupExistingValue(iptype, bytes)

	var blockValue BlockValue
	if exists {
		newMask := currentValue.SourceMask | sourceMask
		blockValue = NewBlockValueWithPreserve(newMask, currentValue.Priority, currentValue.Expiry)
	} else {
		blockValue = NewBlockValue(sourceMask)
	}

	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

// AddRuleWithSourceAndExpiry 添加带过期时间的规则
// duration: 封禁时长（秒），0 表示永久封禁
func (x *Xdp) AddRuleWithSourceAndExpiry(value string, sourceMask uint32, duration int) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}

	currentValue, exists := x.lookupExistingValue(iptype, bytes)

	var blockValue BlockValue
	if exists {
		newMask := currentValue.SourceMask | sourceMask
		newExpiry := currentValue.Expiry
		if duration > 0 {
			newExpiry = uint64(time.Now().Unix()) + uint64(duration)
		}
		blockValue = NewBlockValueWithPreserve(newMask, currentValue.Priority, newExpiry)
	} else {
		blockValue = NewBlockValue(sourceMask)
		if duration > 0 {
			blockValue.Expiry = uint64(time.Now().Unix()) + uint64(duration)
		}
	}

	err = x.updateMap(iptype, bytes, blockValue, true)
	if err == nil {
		x.updateFeatureFlags()
	}
	return err
}

func (x *Xdp) GetRule() ([]Rule, error) {
	x.mapMu.RLock()
	defer x.mapMu.RUnlock()

	var res []Rule
	ipv4List, err := x.ipv4List()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4List...)
	ipv4TrieKeyList, err := x.ipv4TrieKey()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4TrieKeyList...)
	return res, nil
}

// ipv4List 获取 IPv4 精确匹配规则列表
func (x *Xdp) ipv4List() ([]Rule, error) {
	iter := x.objects.BlockIpv4List.Iterate()
	var key []byte
	var value BlockValue
	var res []Rule
	for iter.Next(&key, &value) {
		ip := net.IP(key)
		res = append(res, Rule{
			Key:     ip.String(),
			Value:   value,
			Sources: MaskToSourceIDs(value.SourceMask),
		})
	}
	if err := iter.Err(); err != nil {
		return []Rule{}, err
	}
	return res, nil
}

// ipv4TrieKey 获取 IPv4 CIDR 规则列表
func (x *Xdp) ipv4TrieKey() ([]Rule, error) {
	iter := x.objects.BlockIpv4CidrTrie.Iterate()
	var key IPv4TrieKey
	var value BlockValue
	var res []Rule
	for iter.Next(&key, &value) {
		ip := net.IP(key.Addr[:])
		res = append(res, Rule{
			Key:     fmt.Sprintf("%s/%d", ip.String(), key.PrefixLen),
			Value:   value,
			Sources: MaskToSourceIDs(value.SourceMask),
		})
	}
	if err := iter.Err(); err != nil {
		return []Rule{}, err
	}
	return res, nil
}

// BatchAddRules 批量添加规则（高性能）
func (x *Xdp) BatchAddRules(values []string, sourceMask uint32) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	type entry struct {
		iptype utils.IPType
		key    []byte
	}
	entries := make([]entry, 0, len(values))

	for _, value := range values {
		bytes, iptype, err := utils.ParseValueToBytes(value)
		if err != nil {
			logger.Warnf("[XDP] Failed to parse value %s: %v", value, err)
			continue
		}
		keyCopy := make([]byte, len(bytes))
		copy(keyCopy, bytes)
		entries = append(entries, entry{iptype: iptype, key: keyCopy})
	}

	for _, e := range entries {
		currentValue, exists := x.lookupExistingValue(e.iptype, e.key)

		var blockValue BlockValue
		if exists {
			newMask := currentValue.SourceMask | sourceMask
			blockValue = NewBlockValueWithPreserve(newMask, currentValue.Priority, currentValue.Expiry)
		} else {
			blockValue = NewBlockValue(sourceMask)
		}

		if err := x.updateMap(e.iptype, e.key, blockValue, true); err != nil {
			logger.Warnf("[XDP] Failed to update rule for key %v: %v", e.key, err)
		}
	}

	x.updateFeatureFlags()
	return nil
}

// BatchDeleteRules 批量删除规则
func (x *Xdp) BatchDeleteRules(values []string) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	var errs []error
	for _, value := range values {
		bytes, iptype, err := utils.ParseValueToBytes(value)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		err = x.updateMap(iptype, bytes, BlockValue{}, false)
		if err != nil {
			errs = append(errs, err)
		}
	}
	x.updateFeatureFlags()

	if len(errs) > 0 {
		return fmt.Errorf("batch delete failed with %d errors, first: %v", len(errs), errs[0])
	}
	return nil
}

// UpdateRuleSourceMask 更新规则的来源掩码（按位删除某个来源）
func (x *Xdp) UpdateRuleSourceMask(value string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error) {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return 0, false, false, err
	}

	currentValue, exists := x.lookupExistingValue(iptype, bytes)
	if !exists {
		return 0, false, false, nil
	}

	currentMask := currentValue.SourceMask
	currentPriority := currentValue.Priority
	currentExpiry := currentValue.Expiry

	newMask = currentMask &^ removeMask

	if newMask == currentMask {
		return currentMask, true, false, nil
	}

	if newMask == 0 {
		if err := x.updateMap(iptype, bytes, BlockValue{}, false); err != nil {
			return 0, true, true, fmt.Errorf("delete rule failed: %w", err)
		}
		x.updateFeatureFlags()
		return 0, true, true, nil
	}

	newBlockValue := NewBlockValueWithPreserve(newMask, currentPriority, currentExpiry)
	if err := x.updateMap(iptype, bytes, newBlockValue, true); err != nil {
		return currentMask, true, true, fmt.Errorf("update rule failed: %w", err)
	}
	x.updateFeatureFlags()

	return newMask, true, true, nil
}

// BatchUpdateRuleSourceMask 批量更新规则的来源掩码
func (x *Xdp) BatchUpdateRuleSourceMask(values []string, removeMask uint32) ([]string, error) {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	var toDelete []string
	var errs []error

	for _, value := range values {
		bytes, iptype, err := utils.ParseValueToBytes(value)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s failed: %w", value, err))
			continue
		}

		currentValue, exists := x.lookupExistingValue(iptype, bytes)

		if !exists {
			continue
		}

		currentMask := currentValue.SourceMask
		currentPriority := currentValue.Priority
		currentExpiry := currentValue.Expiry

		newMask := currentMask &^ removeMask

		if newMask == currentMask {
			continue
		}

		if newMask == 0 {
			if err := x.updateMap(iptype, bytes, BlockValue{}, false); err != nil {
				errs = append(errs, fmt.Errorf("delete %s failed: %w", value, err))
			} else {
				toDelete = append(toDelete, value)
			}
		} else {
			newBlockValue := NewBlockValueWithPreserve(newMask, currentPriority, currentExpiry)
			if err := x.updateMap(iptype, bytes, newBlockValue, true); err != nil {
				errs = append(errs, fmt.Errorf("update %s failed: %w", value, err))
			}
		}
	}

	x.updateFeatureFlags()

	if len(errs) > 0 {
		return toDelete, fmt.Errorf("batch update failed with %d errors, first: %v", len(errs), errs[0])
	}
	return toDelete, nil
}
