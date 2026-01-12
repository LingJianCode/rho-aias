// Package geoblocking 地域封禁模块
package geoblocking

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"rho-aias/internal/ebpfs"
)

// Syncer GeoIP 原子同步器
// 负责将 GeoIP 数据安全地同步到内核 eBPF map
type Syncer struct {
	xdp       *ebpfs.Xdp // XDP eBPF 程序接口
	batchSize int         // 批量操作大小
	mu        sync.Mutex // 互斥锁，保证并发安全
}

// NewSyncer 创建新的 GeoIP 同步器
// xdp: XDP eBPF 程序接口
// batchSize: 批量操作的大小限制
func NewSyncer(xdp *ebpfs.Xdp, batchSize int) *Syncer {
	return &Syncer{
		xdp:       xdp,
		batchSize: batchSize,
	}
}

// SyncToKernel 同步 GeoIP 数据到内核 eBPF map（增量更新）
// 通过计算当前规则与新数据的差异，实现平滑更新
func (s *Syncer) SyncToKernel(data *GeoIPData, config *GeoConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 获取当前内核中的所有 GeoIP 规则
	currentRules, err := s.xdp.GetGeoIPRules()
	if err != nil {
		return fmt.Errorf("get current rules failed: %w", err)
	}

	// 2. 计算差异
	toAdd, toRemove := s.diff(currentRules, data)

	log.Printf("[GeoSyncer] Current: %d, New: %d, ToAdd: %d, ToRemove: %d",
		len(currentRules), data.TotalCount(), len(toAdd), len(toRemove))

	// 3. 批量删除需要移除的规则
	if len(toRemove) > 0 {
		if err := s.batchDelete(toRemove); err != nil {
			return fmt.Errorf("batch delete failed: %w", err)
		}
		log.Printf("[GeoSyncer] Removed %d rules", len(toRemove))
	}

	// 4. 批量添加需要新增的规则
	if len(toAdd) > 0 {
		if err := s.batchAdd(toAdd); err != nil {
			return fmt.Errorf("batch add failed: %w", err)
		}
		log.Printf("[GeoSyncer] Added %d rules", len(toAdd))
	}

	// 5. 只有成功加载规则才启用地域过滤
	if data.TotalCount() > 0 {
		mode := uint32(0) // whitelist
		if config.Mode == "blacklist" {
			mode = 1
		}
		// 数据成功加载，启用地域过滤
		if err := s.xdp.UpdateGeoConfig(true, mode); err != nil {
			return fmt.Errorf("update geo config failed: %w", err)
		}
		log.Printf("[GeoSyncer] Geo-blocking ACTIVATED with %d rules", data.TotalCount())
	} else {
		log.Printf("[GeoSyncer] No rules loaded, geo-blocking NOT activated")
		// 保持 enabled=0，不更新 geo_config
	}

	return nil
}

// diff 计算当前规则和新 GeoIP 数据的差异
// 返回需要添加和需要删除的规则列表
func (s *Syncer) diff(current []string, newData *GeoIPData) (toAdd, toRemove []string) {
	// 构建当前规则的集合
	currentSet := make(map[string]bool)
	for _, r := range current {
		currentSet[r] = true
	}

	// 构建新数据的规则集合
	newSet := make(map[string]bool)
	for _, cidr := range newData.IPv4CIDR {
		newSet[cidr] = true
	}

	// 找出需要删除的规则
	for k := range currentSet {
		if !newSet[k] {
			toRemove = append(toRemove, k)
		}
	}

	// 找出需要添加的规则
	for k := range newSet {
		if !currentSet[k] {
			toAdd = append(toAdd, k)
		}
	}

	return toAdd, toRemove
}

// batchAdd 批量添加 GeoIP 规则到内核 eBPF map
func (s *Syncer) batchAdd(rules []string) error {
	// 分批处理
	for i := 0; i < len(rules); i += s.batchSize {
		end := i + s.batchSize
		if end > len(rules) {
			end = len(rules)
		}
		batch := rules[i:end]

		if err := s.xdp.BatchAddGeoIPRules(batch); err != nil {
			return fmt.Errorf("batch add rules [%d:%d] failed: %w", i, end, err)
		}
	}
	return nil
}

// batchDelete 批量删除内核 eBPF map 中的 GeoIP 规则
func (s *Syncer) batchDelete(rules []string) error {
	// 分批处理
	for i := 0; i < len(rules); i += s.batchSize {
		end := i + s.batchSize
		if end > len(rules) {
			end = len(rules)
		}
		batch := rules[i:end]

		if err := s.xdp.BatchDeleteGeoIPRules(batch); err != nil {
			return fmt.Errorf("batch delete rules [%d:%d] failed: %w", i, end, err)
		}
	}
	return nil
}

// LoadAll 直接加载所有 GeoIP 规则到内核（用于初始化）
// 跳过差异计算，直接批量添加
// 适用于：启动时从缓存加载
func (s *Syncer) LoadAll(data *GeoIPData, config *GeoConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 直接批量添加，跳过差异计算
	if len(data.IPv4CIDR) > 0 {
		if err := s.batchAdd(data.IPv4CIDR); err != nil {
			return fmt.Errorf("load all failed: %w", err)
		}
		log.Printf("[GeoSyncer] Loaded %d rules from cache", len(data.IPv4CIDR))
	}

	// 同样逻辑：有规则才启用地域过滤
	if data.TotalCount() > 0 {
		mode := uint32(0) // whitelist
		if config.Mode == "blacklist" {
			mode = 1
		}
		// 数据成功加载，启用地域过滤
		if err := s.xdp.UpdateGeoConfig(true, mode); err != nil {
			return fmt.Errorf("update geo config failed: %w", err)
		}
		log.Printf("[GeoSyncer] Geo-blocking ACTIVATED with %d rules from cache", data.TotalCount())
	} else {
		log.Printf("[GeoSyncer] No rules in cache, geo-blocking NOT activated")
	}

	return nil
}

// countryToCode 将国家代码转换为 uint32
// 例如: "CN" -> 0x434e0000 ('C' << 24 | 'N' << 16)
func countryToCode(country string) uint32 {
	if len(country) < 2 {
		return 0
	}
	// 将两个字符转换为 uint32 (大端序)
	code := uint32(country[0])<<24 | uint32(country[1])<<16
	return code
}

// cidrToLPMKey 将 CIDR 字符串转换为 LPM trie key
// 格式: "1.0.0.0/24,CN" -> prefixlen=24, addr=1.0.0.0
func cidrToLPMKey(cidrWithCountry string) (uint32, []byte, error) {
	// 分离 CIDR 和国家代码
	parts := strings.Split(cidrWithCountry, ",")
	if len(parts) < 1 {
		return 0, nil, fmt.Errorf("invalid format")
	}

	cidr := parts[0]

	// 解析 CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, nil, fmt.Errorf("parse CIDR failed: %w", err)
	}

	ones, _ := ipNet.Mask.Size()

	// 将 IP 地址转换为 4 字节
	ip := ipNet.IP.To4()
	if ip == nil {
		return 0, nil, fmt.Errorf("not an IPv4 address")
	}

	return uint32(ones), ip, nil
}
