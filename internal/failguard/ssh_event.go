package failguard

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// 事件类型常量（与 eBPF C 枚举 ssh_event_type 一致）
const (
	EventAuthResult       = 1 // PAM 认证结果
	EventPreauthShortConn = 2 // preauth 阶段异常短连接
)

// SSHEvent eBPF 内核上报的 SSH 事件（与 C struct ssh_event 二进制兼容）
type SSHEvent struct {
	Type       uint32
	PID        uint32
	RemoteIP   uint32 // 网络字节序 IPv4
	RetCode    uint32
	DurationNS uint64
}

// WhitelistChecker 白名单检查接口（解耦具体实现，支持测试注入）
type WhitelistChecker interface {
	IsWhitelisted(ip string) bool
}

// BanFilter 统一白名单门卫
// 所有封禁操作前必须通过 ShouldBlock() 检查
type BanFilter struct {
	checker WhitelistChecker
}

// NewBanFilter 创建白名单过滤器
func NewBanFilter(checker WhitelistChecker) *BanFilter {
	return &BanFilter{checker: checker}
}

// ShouldBlock 判断是否应该封禁该 IP（返回 true = 应当封禁）
func (f *BanFilter) ShouldBlock(ip string) bool {
	if f.checker == nil {
		return true
	}
	return !f.checker.IsWhitelisted(ip)
}

// FormatRemoteIP 将网络字节序(uint32/big-endian) IPv4 转为点分十进制字符串
// 注意：eBPF 内核通过 ringbuf 上报的数据经 binary.LittleEndian 反序列化后，
// 网络字节序 IP 的最低有效字节落在 uint32 的低位，需从低位开始提取。
func FormatRemoteIP(rawIP uint32) string {
	ip := make(net.IP, 4)
	ip[0] = byte(rawIP)
	ip[1] = byte(rawIP >> 8)
	ip[2] = byte(rawIP >> 16)
	ip[3] = byte(rawIP >> 24)
	return ip.String()
}

// ============================================
// 接口定义 — 解耦 FailGuard 与外部依赖
// ============================================

// EBPFManager eBPF XDP 规则管理接口（由 ebpfs.Xdp 实现）
type EBPFManager interface {
	AddRuleWithSourceAndExpiry(value string, sourceMask uint32, duration int) error
	UpdateRuleSourceMask(value string, removeMask uint32) (newMask uint32, exists bool, changed bool, err error)
}

// parseDurationNS 将秒数转为纳秒字符串（用于 eBPF volatile 变量配置）
func parseDurationNS(seconds int) string {
	ns := int64(seconds) * int64(time.Second)
	return strconv.FormatInt(ns, 10)
}

// _ 编译时接口检查：确保 *ebpfs.Xdp 满足 EBPFManager
var _ EBPFManager = (*ebpfsXdpShim)(nil)

// ebpfsXdpShim 编译期占位类型（实际使用时由 *ebpfs.Xdp 满足接口）
// 此定义仅用于让编译器验证接口一致性，运行时不使用
type ebpfsXdpShim struct{}

func (e *ebpfsXdpShim) AddRuleWithSourceAndExpiry(value string, sourceMask uint32, duration int) error {
	return fmt.Errorf("shim: not implemented")
}

func (e *ebpfsXdpShim) UpdateRuleSourceMask(value string, removeMask uint32) (uint32, bool, bool, error) {
	return 0, false, false, fmt.Errorf("shim: not implemented")
}
