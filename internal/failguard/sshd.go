// Package failguard SSH 防爆破模块
// 参考 fail2ban filter.d/sshd.conf 内置正则规则
package failguard

import (
	"fmt"
	"regexp"
	"strings"

	"rho-aias/utils"
)

// hostPlaceholder fail2ban 约定的 IP 占位符
const hostPlaceholder = "<HOST>"

// hostCaptureGroup 用于替换 <HOST> 的命名捕获组正则
const hostCaptureGroup = `(?P<host>` + utils.IPv4RegexPatternRaw + `)`

// DefaultSSHDNormalFailRegex normal 模式：仅匹配 SSH 认证失败
// 参考 fail2ban filter.d/sshd.conf 的 normal 模式规则
// <HOST> 占位符在运行时替换为 IP 正则捕获组
var DefaultSSHDNormalFailRegex = []string{
	// 密码认证失败
	`Failed \w+ for (?:invalid user )?(\S+) from <HOST> port \d+ ssh2`,
	// 无效用户
	`Invalid user (\S+) from <HOST>`,
	// 非法用户（旧版 sshd 写法）
	`[iI]llegal user (\S+) from <HOST>`,
	// PAM 认证失败
	`pam_unix\(sshd:auth\): auth failure;.*rhost=<HOST>`,
	// PAM 认证失败（通用格式）
	`pam_unix\(sshd:auth\): authentication failure;.*rhost=<HOST>`,
	// 最大尝试次数
	`Maximum authentication attempts exceeded for .* from <HOST>`,
	// 最大尝试次数（另一格式）
	`Maximum authentication attempts exceeded for <HOST>`,
	// 认证错误/失败
	`Authentication failure (?:for )?.* from <HOST>`,
	// PAM 认证失败（简洁格式）
	`pam_succeed_if\(sshd:auth\): requirement .* not met by user`,
	// 用户不存在（PAM）
	`User not known to the underlying authentication module for .* from <HOST>`,
	// ROOT 登录被拒绝
	`ROOT LOGIN REFUSED.*from <HOST>`,
	// 账户被锁定
	`userauth_pubkey: locked account .* from <HOST>`,
	`Disconnected from authenticating user .* <HOST>`,
	// 认证失败（PAM 模块报告）
	`error: PAM: Authentication failure for .* from <HOST>`,
	// 认证错误
	`error: Received disconnect from <HOST>.*Auth fail`,
}

// DefaultSSHDDDOSFailRegex ddos 模式：normal + preauth 阶段异常连接
// 这些模式匹配的 IP 即使没有完成认证也可能被封禁
var DefaultSSHDDDOSFailRegex = []string{
	// 未收到识别字符串（扫描器连接后不发数据）
	`Did not receive identification string from <HOST>`,
	// 认证超时
	`Timeout before authentication for <HOST>`,
	// 输入过大
	`input_userauth_request: excessive input from <HOST>`,
	// 连接被拒绝（TCP Wrapper）
	`refused connect from <HOST>`,
	// 畸形数据包
	`Corrupted MAC on input from <HOST>`,
	// preauth 阶段连接异常（closed/reset，仅限 preauth 阶段）
	`Connection (?:closed|reset) by (?:authenticating user \S+ )?<HOST> port \d+ \[preauth\]`,
}

// DefaultSSHDAggressiveFailRegex aggressive 模式：ddos + 协议协商失败
// 最严格模式，可能产生少量误报，适用于高安全要求场景
var DefaultSSHDAggressiveFailRegex = []string{
	// 协议版本错误
	`Bad protocol version identification '(?:[^']+)' from <HOST>`,
	// 协议协商失败（无法协商密钥交换方法）
	`fatal: Unable to negotiate with <HOST>: no matching (?:key exchange|host key) method found`,
	`fatal: Unable to negotiate with <HOST>: no matching cipher found`,
	`fatal: Unable to negotiate with <HOST>: no matching MAC found`,
	`fatal: Unable to negotiate with <HOST>: no matching compression method found`,
	// 协议不匹配
	`no matching .+ found: client .+ server .+ from <HOST>`,
	// banner exchange 异常（格式错误，通常是扫描/探测行为）
	`banner exchange: Connection from <HOST> port \d+: \S+`,
}

// GetFailRegexByMode 根据模式返回对应的失败正则列表
// normal → 仅认证失败
// ddos → 认证失败 + preauth 异常
// aggressive → ddos + 协议协商失败
func GetFailRegexByMode(mode string) []string {
	switch mode {
	case "aggressive":
		return append(append([]string{}, DefaultSSHDNormalFailRegex...), append(DefaultSSHDDDOSFailRegex, DefaultSSHDAggressiveFailRegex...)...)
	case "ddos":
		return append([]string{}, append(DefaultSSHDNormalFailRegex, DefaultSSHDDDOSFailRegex...)...)
	default:
		return DefaultSSHDNormalFailRegex
	}
}

// DefaultSSHDIgnoreRegex 默认忽略正则（匹配到的行不触发计数）
var DefaultSSHDIgnoreRegex = []string{
	// 认证成功
	`Accepted \w+ for .* from <HOST>`,
	// 正常连接（排除 banner exchange 等异常场景）
	`^.*Connection from <HOST> port \d+$`,
	// 断开连接（非 preauth）
	`Disconnected from <HOST>`,
}

// compileRegex 将正则模式列表编译为正则表达式，自动替换 <HOST> 占位符
func compileRegex(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		replaced := strings.ReplaceAll(pattern, hostPlaceholder, hostCaptureGroup)
		re, err := regexp.Compile(replaced)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex %q: %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}
