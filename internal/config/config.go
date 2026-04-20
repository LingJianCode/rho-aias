package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// Config 配置结构
type Config struct {
	Server           ServerConfig           `yaml:"server"`
	Log              LogConfig              `yaml:"log"`
	Ebpf             EbpfConfig             `yaml:"ebpf"`
	Intel            IntelConfig            `yaml:"intel"`
	GeoBlocking      GeoBlockingConfig      `yaml:"geo_blocking"`
	Manual           ManualConfig           `yaml:"manual"`
	Auth             AuthConfig             `yaml:"auth"`
	Business         BusinessConfig         `yaml:"business"`
	BlockLog         BlockLogConfig         `yaml:"blocklog"`
	WAF              WAFConfig              `yaml:"waf"`
	RateLimit        RateLimitConfig        `yaml:"rate_limit"`
	FailGuard        FailGuardConfig        `yaml:"failguard"`
	AnomalyDetection AnomalyDetectionConfig `yaml:"anomaly_detection"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level         string `yaml:"level"`          // 日志级别: debug/info/warn/error
	Format        string `yaml:"format"`         // 输出格式: console/json
	OutputDir     string `yaml:"output_dir"`     // 日志目录
	MaxAgeDays    int    `yaml:"max_age_days"`   // 日志保留天数
	RotationHours int    `yaml:"rotation_hours"` // 按小时分割
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type EbpfConfig struct {
	InterfaceName string `yaml:"interface_name"`
}

// IntelConfig 情报配置
type IntelConfig struct {
	Enabled        bool                   `yaml:"enabled"`         // 总开关
	PersistenceDir string                 `yaml:"persistence_dir"` // 持久化目录
	Sources        map[string]IntelSource `yaml:"sources"`         // 情报源配置 (map 结构支持动态添加)
	BatchSize      int                    `yaml:"batch_size"`      // 批量更新大小
}

// IntelSource 单个情报源配置
type IntelSource struct {
	Enabled  bool   `yaml:"enabled"`  // 是否启用
	Periodic bool   `yaml:"periodic"` // 是否启用周期性调度（默认 true）
	Schedule string `yaml:"schedule"` // Cron 表达式 (如: "0 * * * *" 表示每小时整点)
	URL      string `yaml:"url"`      // 数据源 URL
	Format   string `yaml:"format"`   // 格式类型 (ipsum/spamhaus)
}

// GeoBlockingConfig 地域封禁配置
type GeoBlockingConfig struct {
	Enabled              bool                   `yaml:"enabled"`                // 总开关
	Mode                 string                 `yaml:"mode"`                   // "whitelist" 或 "blacklist"
	AllowedCountries     []string               `yaml:"allowed_countries"`      // 允许的国家代码列表
	AllowPrivateNetworks bool                   `yaml:"allow_private_networks"` // 允许私有网段绕过地域检查
	PersistenceDir       string                 `yaml:"persistence_dir"`        // 持久化目录
	BatchSize            int                    `yaml:"batch_size"`             // 批量更新大小
	Sources              map[string]GeoIPSource `yaml:"sources"`                // GeoIP 数据源配置
}

// GeoIPSource GeoIP 数据源配置
// 数据由外部工具下载后托管在 nginx 文件服务器
type GeoIPSource struct {
	Enabled  bool   `yaml:"enabled"`  // 是否启用
	Periodic bool   `yaml:"periodic"` // 是否启用周期性调度（默认 true）
	Schedule string `yaml:"schedule"` // Cron 表达式
	URL      string `yaml:"url"`      // CSV 文件 URL
	Format   string `yaml:"format"`   // maxmind, dbip 等
}

// ManualConfig 手动规则配置(包含黑名单和白名单)
type ManualConfig struct {
	PersistenceDir string `yaml:"persistence_dir"` // 持久化目录
	AutoLoad       bool   `yaml:"auto_load"`       // 启动时自动加载
}

// AuthConfig 认证配置
type AuthConfig struct {
	JWTSecret       string         `yaml:"jwt_secret"`       // JWT 密钥（建议从环境变量读取）
	JWTIssuer       string         `yaml:"jwt_issuer"`       // JWT 签发者
	TokenDuration   int            `yaml:"token_duration"`   // Token 有效期（分钟）
	DatabasePath    string         `yaml:"database_path"`    // 认证数据库路径
	CaptchaEnabled  bool           `yaml:"captcha_enabled"`  // 是否启用验证码
	CaptchaDuration int            `yaml:"captcha_duration"` // 验证码有效期（分钟）
	APIKeys         []APIKeyConfig `yaml:"api_keys"`         // 预定义的 API Key
}

// BusinessConfig 业务数据配置
type BusinessConfig struct {
	DatabasePath string `yaml:"database_path"` // 业务数据库路径（封禁记录、情报状态等）
}

// APIKeyConfig API Key 配置
type APIKeyConfig struct {
	Name        string   `yaml:"name"`        // Key 名称
	Key         string   `yaml:"key"`         // API Key（支持环境变量 ${VAR}）
	Permissions []string `yaml:"permissions"` // 权限列表，["*"] 表示全部权限
}

// BlockLogConfig 阻断日志配置（始终持久化）
type BlockLogConfig struct {
	LogDir          string `yaml:"log_dir"`           // 已废弃：日志目录（SQLite 替代 JSONL 后不再使用）
	MemoryCacheSize int    `yaml:"memory_cache_size"` // 内存缓存大小（用于实时查询）
	BufferSize      int    `yaml:"buffer_size"`       // 异步写入缓冲区大小
	FlushInterval   int    `yaml:"flush_interval"`    // 刷盘间隔（秒）

	// 以下字段由动态配置恢复写入（非 YAML），供 LoadCachedRules 恢复 eBPF 事件上报配置
	EventsEnabled    bool   `yaml:"-"`
	EventsSampleRate uint32 `yaml:"-"`
}

// FailGuardConfig SSH 防爆破配置
// 参考 fail2ban 的核心功能：日志匹配 + 滑动窗口计数 + 达阈值封禁
// 模式说明：normal=认证失败, ddos=认证失败+preauth异常, aggressive=ddos+协议协商失败
type FailGuardConfig struct {
	Enabled         bool     `yaml:"enabled"`           // 是否启用 FailGuard
	LogPath         string   `yaml:"log_path"`          // 监控的日志文件路径
	OffsetStateFile string   `yaml:"offset_state_file"` // 偏移量持久化文件路径（默认 ./data/failguard_offset.json）
	Mode            string   `yaml:"mode"`              // 检测模式: normal/ddos/aggressive（默认 normal）
	FailRegex       []string `yaml:"fail_regex"`        // 失败匹配正则（留空使用内置默认）
	IgnoreRegex     []string `yaml:"ignore_regex"`      // 忽略匹配正则（留空使用内置默认）
	IgnoreIPs       []string `yaml:"ignore_ips"`        // 忽略的 IP/CIDR 列表（白名单）
	MaxRetry        int      `yaml:"max_retry"`         // 触发封禁的失败次数阈值
	FindTime        int      `yaml:"find_time"`         // 滑动窗口时长（秒）
	BanDuration     int      `yaml:"ban_duration"`      // 封禁时长（秒）
}

// WAFConfig WAF 日志监控配置
type WAFConfig struct {
	Enabled         bool   `yaml:"enabled"`           // 是否启用 WAF 日志监控
	WAFLogPath      string `yaml:"waf_log_path"`      // WAF 审计日志路径（Caddy + Coraza）
	BanDuration     int    `yaml:"ban_duration"`      // 封禁时长（秒）
	OffsetStateFile string `yaml:"offset_state_file"` // 偏移量持久化文件路径（默认 ./data/waf_offset.json）
}

// RateLimitConfig Rate Limit 日志监控配置
type RateLimitConfig struct {
	Enabled         bool   `yaml:"enabled"`           // 是否启用 Rate Limit 日志监控
	LogPath         string `yaml:"log_path"`          // Rate Limit 日志路径
	BanDuration     int    `yaml:"ban_duration"`      // 封禁时长（秒）
	OffsetStateFile string `yaml:"offset_state_file"` // 偏移量持久化文件路径（默认 ./data/ratelimit_offset.json）
}

// AnomalyDetectionConfig 异常检测配置
type AnomalyDetectionConfig struct {
	Enabled         bool           `yaml:"enabled" json:"enabled"`                   // 总开关
	SampleRate      int            `yaml:"sample_rate" json:"sample_rate"`           // 采样率 1/N（100 表示 1%）
	CheckInterval   int            `yaml:"check_interval" json:"check_interval"`     // 检测间隔（秒）
	MinPackets      int            `yaml:"min_packets" json:"min_packets"`           // 最小包数（少于此值不检测）
	CleanupInterval int            `yaml:"cleanup_interval" json:"cleanup_interval"` // 清理过期数据间隔（秒）
	Ports           []int          `yaml:"ports" json:"ports"`                       // 需要检测的端口列表（同时应用于 TCP/UDP，为空则检测所有端口）
	Baseline        BaselineConfig `yaml:"baseline" json:"baseline"`                 // 3σ 基线配置
	Attacks         AttacksConfig  `yaml:"attacks" json:"attacks"`                   // 攻击类型配置
}

// BaselineConfig 3σ 基线检测配置
type BaselineConfig struct {
	MinSampleCount  int     `yaml:"min_sample_count" json:"min_sample_count"` // 最小样本数
	SigmaMultiplier float64 `yaml:"sigma_multiplier" json:"sigma_multiplier"` // σ 倍数
	MinThreshold    int     `yaml:"min_threshold" json:"min_threshold"`       // 最小 PPS 阈值
	MaxAge          int     `yaml:"max_age" json:"max_age"`                   // 基线最大年龄（秒）
	BlockDuration   int     `yaml:"block_duration" json:"block_duration"`     // 封禁时长（秒）
}

// AttacksConfig 攻击类型配置
type AttacksConfig struct {
	SynFlood  AttackConfig `yaml:"syn_flood" json:"syn_flood"`
	UdpFlood  AttackConfig `yaml:"udp_flood" json:"udp_flood"`
	IcmpFlood AttackConfig `yaml:"icmp_flood" json:"icmp_flood"`
	AckFlood  AttackConfig `yaml:"ack_flood" json:"ack_flood"`
}

// AttackConfig 单个攻击类型配置
type AttackConfig struct {
	Enabled        bool    `yaml:"enabled" json:"enabled"`                 // 是否启用
	RatioThreshold float64 `yaml:"ratio_threshold" json:"ratio_threshold"` // 协议占比阈值
	BlockDuration  int     `yaml:"block_duration" json:"block_duration"`   // 封禁时长（秒）
	MinPackets     int     `yaml:"min_packets" json:"min_packets"`         // 触发检测的最小包数（0 表示使用默认值）
}

func NewConfig(fileName string) (*Config, error) {
	// 打开 YAML 文件
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	// 创建解析器
	decoder := yaml.NewDecoder(file)

	// 配置对象
	var config Config

	// 解析 YAML 数据
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("error decoding config YAML: %w", err)
	}

	applyDefaults(&config)

	// 展开环境变量
	config.expandEnvVars()

	return &config, nil
}

// applyDefaults 设置配置默认值
func applyDefaults(config *Config) {
	// Auth 默认值
	setIfZero(&config.Auth.TokenDuration, 1440) // 默认 24 小时
	setIfZero(&config.Auth.CaptchaDuration, 5)  // 默认 5 分钟
	setIfEmpty(&config.Auth.DatabasePath, "./data/auth.db")

	// Business 默认值
	setIfEmpty(&config.Business.DatabasePath, "./data/business.db")

	// Log 默认值
	setIfEmpty(&config.Log.Level, "info")
	setIfEmpty(&config.Log.Format, "console")
	setIfEmpty(&config.Log.OutputDir, "./logs")
	setIfZero(&config.Log.MaxAgeDays, 30)
	setIfZero(&config.Log.RotationHours, 1)

	// BlockLog 默认值
	setIfEmpty(&config.BlockLog.LogDir, "./logs/blocklog")
	setIfZero(&config.BlockLog.MemoryCacheSize, 10000)
	setIfZero(&config.BlockLog.BufferSize, 1000)
	setIfZero(&config.BlockLog.FlushInterval, 5) // 默认 5 秒

	// Intel sources 默认值
	for name, source := range config.Intel.Sources {
		source.Periodic = true
		config.Intel.Sources[name] = source
	}

	// GeoBlocking sources 默认值
	for name, source := range config.GeoBlocking.Sources {
		source.Periodic = true
		config.GeoBlocking.Sources[name] = source
	}

	// FailGuard 默认值
	setIfEmpty(&config.FailGuard.Mode, "normal")
	setIfEmpty(&config.FailGuard.LogPath, "/var/log/auth.log")
	setIfZero(&config.FailGuard.MaxRetry, 5)
	setIfZero(&config.FailGuard.FindTime, 600)     // 默认 10 分钟
	setIfZero(&config.FailGuard.BanDuration, 3600) // 默认 1 小时
	setIfEmpty(&config.FailGuard.OffsetStateFile, "./data/failguard_offset.json")

	// WAF 默认值
	setIfEmpty(&config.WAF.WAFLogPath, "/logs/waf_audit.log")
	setIfZero(&config.WAF.BanDuration, 3600) // 默认 1 小时
	setIfEmpty(&config.WAF.OffsetStateFile, "./data/waf_offset.json")

	// RateLimit 默认值
	setIfEmpty(&config.RateLimit.LogPath, "/logs/rate_limit.log")
	setIfZero(&config.RateLimit.BanDuration, 3600) // 默认 1 小时
	setIfEmpty(&config.RateLimit.OffsetStateFile, "./data/ratelimit_offset.json")

	// AnomalyDetection 默认值
	setIfZero(&config.AnomalyDetection.SampleRate, 100)
	setIfZero(&config.AnomalyDetection.CheckInterval, 1)
	setIfZero(&config.AnomalyDetection.MinPackets, 100)
	setIfZero(&config.AnomalyDetection.CleanupInterval, 300)

	// Baseline 默认值
	setIfZero(&config.AnomalyDetection.Baseline.MinSampleCount, 10)
	setIfZeroFloat(&config.AnomalyDetection.Baseline.SigmaMultiplier, 3.0)
	setIfZero(&config.AnomalyDetection.Baseline.MinThreshold, 100)
	setIfZero(&config.AnomalyDetection.Baseline.MaxAge, 1800)
	setIfZero(&config.AnomalyDetection.Baseline.BlockDuration, 60)

	// Attack 默认值
	applyAttackDefaults(&config.AnomalyDetection.Attacks.SynFlood, 0.5, 60, 1000)
	applyAttackDefaults(&config.AnomalyDetection.Attacks.UdpFlood, 0.8, 60, 1000)
	applyAttackDefaults(&config.AnomalyDetection.Attacks.IcmpFlood, 0.5, 60, 100)
	applyAttackDefaults(&config.AnomalyDetection.Attacks.AckFlood, 0.8, 60, 1000)
}

// setIfZero 当 *v 为零值时设为 def
func setIfZero[T ~int | ~uint | ~uint32 | ~uint64 | ~int64](v *T, def T) {
	if *v == 0 {
		*v = def
	}
}

// setIfZeroFloat 当 *v 为零值时设为 def（float64 专用）
func setIfZeroFloat(v *float64, def float64) {
	if *v == 0 {
		*v = def
	}
}

// setIfEmpty 当 s 为空字符串时设为 def
func setIfEmpty(s *string, def string) {
	if *s == "" {
		*s = def
	}
}

// applyAttackDefaults 设置单个攻击类型的默认值
func applyAttackDefaults(a *AttackConfig, ratioThreshold float64, blockDuration, minPackets int) {
	if a.RatioThreshold == 0 {
		a.RatioThreshold = ratioThreshold
	}
	if a.BlockDuration == 0 {
		a.BlockDuration = blockDuration
	}
	if a.MinPackets == 0 {
		a.MinPackets = minPackets
	}
}

// expandEnvVars 展开配置中的环境变量（支持 ${VAR_NAME} 格式）
func (c *Config) expandEnvVars() {
	// 展开 API Key 中的环境变量
	for i := range c.Auth.APIKeys {
		c.Auth.APIKeys[i].Key = os.ExpandEnv(c.Auth.APIKeys[i].Key)
	}
}
