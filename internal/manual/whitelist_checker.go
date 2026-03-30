package manual

import (
	"net"
	"sync"
)

// WhitelistChecker 用户态白名单检查器
// 维护白名单规则的内存索引，提供高效的 IP/CIDR 匹配检查，
// 避免封禁模块将白名单 IP 持续写入黑名单 map
type WhitelistChecker struct {
	mu sync.RWMutex

	// 精确 IP 匹配（key 为规范化后的 IP 字符串）
	exactIPs map[string]struct{}
	// CIDR 范围匹配（预解析的网络列表）
	cidrNets []*net.IPNet
}

// NewWhitelistChecker 创建白名单检查器
func NewWhitelistChecker() *WhitelistChecker {
	return &WhitelistChecker{
		exactIPs: make(map[string]struct{}),
	}
}

// LoadFromCache 从白名单缓存数据批量加载规则
func (wc *WhitelistChecker) LoadFromCache(data *WhitelistCacheData) {
	if data == nil {
		return
	}

	newExactIPs := make(map[string]struct{})
	var newCIDRs []*net.IPNet

	for value := range data.Rules {
		ip := net.ParseIP(value)
		if ip != nil {
			newExactIPs[ip.String()] = struct{}{}
			continue
		}

		_, ipNet, err := net.ParseCIDR(value)
		if err == nil && ipNet != nil {
			newCIDRs = append(newCIDRs, ipNet)
			continue
		}

		// 无法识别的格式，按原样做精确匹配兜底
		newExactIPs[value] = struct{}{}
	}

	wc.mu.Lock()
	wc.exactIPs = newExactIPs
	wc.cidrNets = newCIDRs
	wc.mu.Unlock()
}

// Add 添加白名单规则（实时生效）
func (wc *WhitelistChecker) Add(value string) {
	wc.mu.Lock()
	defer wc.mu.Unlock()

	ip := net.ParseIP(value)
	if ip != nil {
		wc.exactIPs[ip.String()] = struct{}{}
		return
	}

	_, ipNet, err := net.ParseCIDR(value)
	if err == nil && ipNet != nil {
		wc.cidrNets = append(wc.cidrNets, ipNet)
		return
	}

	wc.exactIPs[value] = struct{}{}
}

// Remove 移除白名单规则（实时生效）
func (wc *WhitelistChecker) Remove(value string) {
	wc.mu.Lock()
	defer wc.mu.Unlock()

	ip := net.ParseIP(value)
	if ip != nil {
		delete(wc.exactIPs, ip.String())
		return
	}

	_, ipNet, err := net.ParseCIDR(value)
	if err == nil && ipNet != nil {
		for i, n := range wc.cidrNets {
			if n.String() == ipNet.String() {
				wc.cidrNets = append(wc.cidrNets[:i], wc.cidrNets[i+1:]...)
				break
			}
		}
		return
	}

	delete(wc.exactIPs, value)
}

// IsWhitelisted 检查 IP 是否在白名单中
// 支持精确 IP 匹配和 CIDR 范围匹配
func (wc *WhitelistChecker) IsWhitelisted(ip string) bool {
	wc.mu.RLock()
	defer wc.mu.RUnlock()

	if len(wc.exactIPs) == 0 && len(wc.cidrNets) == 0 {
		return false
	}

	parsedIP := net.ParseIP(ip)

	// 1. 精确匹配
	if parsedIP != nil {
		if _, ok := wc.exactIPs[parsedIP.String()]; ok {
			return true
		}
	} else {
		if _, ok := wc.exactIPs[ip]; ok {
			return true
		}
	}

	// 2. CIDR 范围匹配
	if parsedIP != nil {
		for _, cidr := range wc.cidrNets {
			if cidr.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}
