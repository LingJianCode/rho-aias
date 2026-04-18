package manual

import "errors"

var (
	// ErrWhitelistConflict 白名单冲突：尝试封禁白名单中的 IP/CIDR
	ErrWhitelistConflict = errors.New("IP/CIDR is in whitelist, remove it from whitelist first")

	// ErrRuleConflict 规则冲突：规则已存在
	ErrRuleConflict = errors.New("IP/CIDR already exists in blacklist")

	// ErrProtectedNet 保护网段：尝试删除内置保护网段
	ErrProtectedNet = errors.New("cannot delete built-in protected network segment")
)
