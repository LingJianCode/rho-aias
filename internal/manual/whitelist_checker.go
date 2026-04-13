package manual

import (
	"net"
	"rho-aias/utils"
	"sync"
)

// protectedNets 内置保护网段，不可通过 API 移除
// 用于防止本机回环地址和本机 IP 被封禁导致服务不可用
var protectedNets []*net.IPNet

// InitProtectedNets 初始化保护网段列表
// 需要在 logger 初始化后调用，以便记录添加的本机 IP
func InitProtectedNets(logFunc func(format string, args ...interface{})) []*net.IPNet {
	nets := make([]*net.IPNet, 0)

	// 添加回环地址
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	nets = append(nets, loopback)

	// 添加本机 IP
	if localNets, err := utils.GetLocalIPNets(); err == nil && len(localNets) > 0 {
		ips := make([]string, 0, len(localNets))
		for _, ipNet := range localNets {
			ips = append(ips, ipNet.IP.String())
		}
		if logFunc != nil {
			logFunc("[Whitelist] Adding local IPs to protected list: %v", ips)
		}
		nets = append(nets, localNets...)
	}

	protectedNets = nets
	return nets
}

func init() {
	// 默认初始化（不记录日志）
	InitProtectedNets(nil)
}

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
// 支持精确 IP 匹配、CIDR 范围匹配和内置保护网段（不可移除）
func (wc *WhitelistChecker) IsWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)

	// 0. 内置保护网段检查（优先级最高，不受 Add/Remove/LoadFromCache 影响）
	if parsedIP != nil {
		for _, net := range protectedNets {
			if net.Contains(parsedIP) {
				return true
			}
		}
	}

	wc.mu.RLock()
	defer wc.mu.RUnlock()

	if len(wc.exactIPs) == 0 && len(wc.cidrNets) == 0 {
		return false
	}

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
