// Package failguard SSH 防爆破模块
// 参考 fail2ban filter.d/sshd.conf 内置正则规则
package failguard

import (
	"fmt"
	"regexp"
	"strings"
)

// hostPlaceholder fail2ban 约定的 IP 占位符
const hostPlaceholder = "<HOST>"

// ipPattern 匹配 IPv4 地址的正则表达式
const ipPattern = `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`

// hostCaptureGroup 用于替换 <HOST> 的命名捕获组正则
const hostCaptureGroup = `(?P<host>` + ipPattern + `)`

// DefaultSSHDFailRegex 默认 SSH 认证失败正则（参考 fail2ban filter.d/sshd.conf）
// <HOST> 占位符在运行时替换为 IP 正则捕获组
var DefaultSSHDFailRegex = []string{
	// 密码认证失败
	`Failed \w+ for (?:invalid user )?(\S+) from <HOST> port \d+ ssh2`,
	// 无效用户
	`Invalid user (\S+) from <HOST>`,
	// PAM 认证失败
	`pam_unix\(sshd:auth\): auth failure;.*rhost=<HOST>`,
	// 最大尝试次数
	`Maximum authentication attempts exceeded for .* from <HOST>`,
	// pre-auth 连接异常（closed/reset，兼容有无用户信息）
	`Connection (?:closed|reset) by (?:authenticating user \S+ )?<HOST> port \d+`,
	// banner exchange 异常（格式错误，通常是扫描/探测行为）
	`banner exchange: Connection from <HOST> port \d+: \S+`,
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
