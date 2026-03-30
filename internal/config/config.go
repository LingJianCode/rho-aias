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
	BlockLog         BlockLogConfig         `yaml:"blocklog"`
	WAF              WAFConfig              `yaml:"waf"`
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
	Enabled          bool                   `yaml:"enabled"`            // 总开关
	AutoRefreshOnStart bool                 `yaml:"auto_refresh_on_start"` // 启动时自动刷新
	PersistenceDir   string                 `yaml:"persistence_dir"`   // 持久化目录
	Sources          map[string]IntelSource `yaml:"sources"`           // 情报源配置 (map 结构支持动态添加)
	BatchSize        int                    `yaml:"batch_size"`         // 批量更新大小
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
	Enabled              bool                   `yaml:"enabled"`                 // 总开关
	AutoRefreshOnStart   bool                   `yaml:"auto_refresh_on_start"`  // 启动时自动刷新
	Mode                 string                 `yaml:"mode"`                    // "whitelist" 或 "blacklist"
	AllowedCountries     []string               `yaml:"allowed_countries"`       // 允许的国家代码列表
	AllowPrivateNetworks bool                   `yaml:"allow_private_networks"` // 允许私有网段绕过地域检查
	PersistenceDir       string                 `yaml:"persistence_dir"`        // 持久化目录
	BatchSize            int                    `yaml:"batch_size"`             // 批量更新大小
	Sources              map[string]GeoIPSource `yaml:"sources"`                 // GeoIP 数据源配置
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

// ManualConfig 手动规则配置
type ManualConfig struct {
	Enabled        bool   `yaml:"enabled"`         // 是否启用手动规则持久化
	PersistenceDir string `yaml:"persistence_dir"` // 持久化目录
	AutoLoad       bool   `yaml:"auto_load"`       // 启动时自动加载
}

// AuthConfig 认证配置
type AuthConfig struct {
	Enabled         bool          `yaml:"enabled"`          // 是否启用认证
	JWTSecret       string        `yaml:"jwt_secret"`       // JWT 密钥（建议从环境变量读取）
	JWTIssuer       string        `yaml:"jwt_issuer"`       // JWT 签发者
	TokenDuration   int           `yaml:"token_duration"`   // Token 有效期（分钟）
	DatabasePath    string        `yaml:"database_path"`    // 数据库路径
	CaptchaEnabled  bool          `yaml:"captcha_enabled"`  // 是否启用验证码
	CaptchaDuration int           `yaml:"captcha_duration"` // 验证码有效期（分钟）
	APIKeys         []APIKeyConfig `yaml:"api_keys"`       // 预定义的 API Key
}

// APIKeyConfig API Key 配置
type APIKeyConfig struct {
	Name        string   `yaml:"name"`        // Key 名称
	Key         string   `yaml:"key"`         // API Key（支持环境变量 ${VAR}）
	Permissions []string `yaml:"permissions"` // 权限列表，["*"] 表示全部权限
}

// BlockLogConfig 阻断日志配置
type BlockLogConfig struct {
	Enabled         bool   `yaml:"enabled"`           // 是否启用文件持久化
	LogDir          string `yaml:"log_dir"`           // 日志目录
	MemoryCacheSize int    `yaml:"memory_cache_size"` // 内存缓存大小（用于实时查询）
	BufferSize      int    `yaml:"buffer_size"`       // 异步写入缓冲区大小
	FlushInterval   int    `yaml:"flush_interval"`    // 刷盘间隔（秒）
}

// FailGuardConfig SSH 防爆破配置
// 参考 fail2ban 的核心功能：日志匹配 + 滑动窗口计数 + 达阈值封禁
type FailGuardConfig struct {
	Enabled          bool     `yaml:"enabled"`            // 是否启用 FailGuard
	LogPath          string   `yaml:"log_path"`           // 监控的日志文件路径
	OffsetStateFile  string   `yaml:"offset_state_file"`  // 偏移量持久化文件路径（默认 ./data/failguard_offset.json）
	FailRegex        []string `yaml:"fail_regex"`         // 失败匹配正则（留空使用内置默认）
	IgnoreRegex      []string `yaml:"ignore_regex"`       // 忽略匹配正则（留空使用内置默认）
	IgnoreIPs        []string `yaml:"ignore_ips"`         // 忽略的 IP/CIDR 列表（白名单）
	MaxRetry         int      `yaml:"max_retry"`          // 触发封禁的失败次数阈值
	FindTime         int      `yaml:"find_time"`          // 滑动窗口时长（秒）
	BanDuration      int      `yaml:"ban_duration"`       // 封禁时长（秒）
}

// WAFConfig WAF 日志监控配置
type WAFConfig struct {
	Enabled          bool   `yaml:"enabled"`              // 是否启用 WAF 日志监控
	WAFLogPath       string `yaml:"waf_log_path"`         // WAF 审计日志路径（Caddy + Coraza）
	RateLimitLogPath string `yaml:"rate_limit_log_path"`  // Rate Limit 日志路径
	BanDuration      int    `yaml:"ban_duration"`         // 封禁时长（秒）
	OffsetStateFile  string `yaml:"offset_state_file"`    // 偏移量持久化文件路径（默认 ./data/waf_offset.json）
}

// AnomalyDetectionConfig 异常检测配置
type AnomalyDetectionConfig struct {
	Enabled         bool            `yaml:"enabled"`          // 总开关
	SampleRate      int             `yaml:"sample_rate"`      // 采样率 1/N（100 表示 1%）
	CheckInterval   int             `yaml:"check_interval"`   // 检测间隔（秒）
	MinPackets      int             `yaml:"min_packets"`      // 最小包数（少于此值不检测）
	CleanupInterval int             `yaml:"cleanup_interval"` // 清理过期数据间隔（秒）
	BlockDuration   int             `yaml:"block_duration"`   // 临时封禁时长（秒）
	Ports           []int           `yaml:"ports"`            // 需要检测的端口列表（同时应用于 TCP/UDP，为空则检测所有端口）
	Baseline        BaselineConfig  `yaml:"baseline"`         // 3σ 基线配置
	Attacks         AttacksConfig   `yaml:"attacks"`          // 攻击类型配置
}

// BaselineConfig 3σ 基线检测配置
type BaselineConfig struct {
	MinSampleCount  int     `yaml:"min_sample_count"`  // 最小样本数
	SigmaMultiplier float64 `yaml:"sigma_multiplier"`  // σ 倍数
	MinThreshold    int     `yaml:"min_threshold"`     // 最小 PPS 阈值
	MaxAge          int     `yaml:"max_age"`           // 基线最大年龄（秒）
}

// AttacksConfig 攻击类型配置
type AttacksConfig struct {
	SynFlood  AttackConfig `yaml:"syn_flood"`
	UdpFlood  AttackConfig `yaml:"udp_flood"`
	IcmpFlood AttackConfig `yaml:"icmp_flood"`
	AckFlood  AttackConfig `yaml:"ack_flood"`
}

// AttackConfig 单个攻击类型配置
type AttackConfig struct {
	Enabled        bool    `yaml:"enabled"`
	RatioThreshold float64 `yaml:"ratio_threshold"` // 协议占比阈值
	BlockDuration  int     `yaml:"block_duration"`  // 封禁时长（秒）
	MinPackets     int     `yaml:"min_packets"`     // 触发检测的最小包数（0 表示使用默认值）
}

func NewConfig(fileName string) *Config {
	// 打开 YAML 文件
	file, err := os.Open(fileName)
	if err != nil {
		panic(fmt.Sprintf("Error opening file:%e", err))
	}
	defer file.Close()

	// 创建解析器
	decoder := yaml.NewDecoder(file)

	// 配置对象
	var config Config

	// 解析 YAML 数据
	err = decoder.Decode(&config)
	if err != nil {
		panic(fmt.Sprintf("Error decoding YAML:%e", err))
	}

	// 设置默认值
	if config.Auth.TokenDuration == 0 {
		config.Auth.TokenDuration = 1440 // 默认 24 小时
	}
	if config.Auth.CaptchaDuration == 0 {
		config.Auth.CaptchaDuration = 5 // 默认 5 分钟
	}

	// Log 默认值
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}
	if config.Log.Format == "" {
		config.Log.Format = "console"
	}
	if config.Log.OutputDir == "" {
		config.Log.OutputDir = "./logs"
	}
	if config.Log.MaxAgeDays == 0 {
		config.Log.MaxAgeDays = 30
	}
	if config.Log.RotationHours == 0 {
		config.Log.RotationHours = 1
	}

	// BlockLog 默认值
	if config.BlockLog.LogDir == "" {
		config.BlockLog.LogDir = "./logs/blocklog"
	}
	if config.BlockLog.MemoryCacheSize == 0 {
		config.BlockLog.MemoryCacheSize = 10000
	}
	if config.BlockLog.BufferSize == 0 {
		config.BlockLog.BufferSize = 1000
	}
	if config.BlockLog.FlushInterval == 0 {
		config.BlockLog.FlushInterval = 5 // 默认 5 秒
	}

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
	if config.FailGuard.LogPath == "" {
		config.FailGuard.LogPath = "/var/log/auth.log"
	}
	if config.FailGuard.MaxRetry == 0 {
		config.FailGuard.MaxRetry = 5
	}
	if config.FailGuard.FindTime == 0 {
		config.FailGuard.FindTime = 600 // 默认 10 分钟
	}
	if config.FailGuard.BanDuration == 0 {
		config.FailGuard.BanDuration = 3600 // 默认 1 小时
	}

	// WAF 默认值
	if config.WAF.WAFLogPath == "" {
		config.WAF.WAFLogPath = "/logs/waf_audit.log"
	}
	if config.WAF.RateLimitLogPath == "" {
		config.WAF.RateLimitLogPath = "/logs/rate_limit.log"
	}
	if config.WAF.BanDuration == 0 {
		config.WAF.BanDuration = 3600 // 默认 1 小时
	}

	// AnomalyDetection 默认值
	if config.AnomalyDetection.SampleRate == 0 {
		config.AnomalyDetection.SampleRate = 100
	}
	if config.AnomalyDetection.CheckInterval == 0 {
		config.AnomalyDetection.CheckInterval = 1
	}
	if config.AnomalyDetection.MinPackets == 0 {
		config.AnomalyDetection.MinPackets = 100
	}
	if config.AnomalyDetection.CleanupInterval == 0 {
		config.AnomalyDetection.CleanupInterval = 300
	}
	if config.AnomalyDetection.BlockDuration == 0 {
		config.AnomalyDetection.BlockDuration = 60
	}

	// Baseline 默认值
	if config.AnomalyDetection.Baseline.MinSampleCount == 0 {
		config.AnomalyDetection.Baseline.MinSampleCount = 10
	}
	if config.AnomalyDetection.Baseline.SigmaMultiplier == 0 {
		config.AnomalyDetection.Baseline.SigmaMultiplier = 3.0
	}
	if config.AnomalyDetection.Baseline.MinThreshold == 0 {
		config.AnomalyDetection.Baseline.MinThreshold = 100
	}
	if config.AnomalyDetection.Baseline.MaxAge == 0 {
		config.AnomalyDetection.Baseline.MaxAge = 1800
	}

	// Attack 默认值
	if config.AnomalyDetection.Attacks.SynFlood.RatioThreshold == 0 {
		config.AnomalyDetection.Attacks.SynFlood.RatioThreshold = 0.5
	}
	if config.AnomalyDetection.Attacks.SynFlood.BlockDuration == 0 {
		config.AnomalyDetection.Attacks.SynFlood.BlockDuration = 60
	}
	if config.AnomalyDetection.Attacks.SynFlood.MinPackets == 0 {
		config.AnomalyDetection.Attacks.SynFlood.MinPackets = 1000
	}
	if config.AnomalyDetection.Attacks.UdpFlood.RatioThreshold == 0 {
		config.AnomalyDetection.Attacks.UdpFlood.RatioThreshold = 0.8
	}
	if config.AnomalyDetection.Attacks.UdpFlood.BlockDuration == 0 {
		config.AnomalyDetection.Attacks.UdpFlood.BlockDuration = 60
	}
	if config.AnomalyDetection.Attacks.UdpFlood.MinPackets == 0 {
		config.AnomalyDetection.Attacks.UdpFlood.MinPackets = 1000
	}
	if config.AnomalyDetection.Attacks.IcmpFlood.RatioThreshold == 0 {
		config.AnomalyDetection.Attacks.IcmpFlood.RatioThreshold = 0.5
	}
	if config.AnomalyDetection.Attacks.IcmpFlood.BlockDuration == 0 {
		config.AnomalyDetection.Attacks.IcmpFlood.BlockDuration = 60
	}
	if config.AnomalyDetection.Attacks.IcmpFlood.MinPackets == 0 {
		config.AnomalyDetection.Attacks.IcmpFlood.MinPackets = 100
	}
	if config.AnomalyDetection.Attacks.AckFlood.RatioThreshold == 0 {
		config.AnomalyDetection.Attacks.AckFlood.RatioThreshold = 0.8
	}
	if config.AnomalyDetection.Attacks.AckFlood.BlockDuration == 0 {
		config.AnomalyDetection.Attacks.AckFlood.BlockDuration = 60
	}
	if config.AnomalyDetection.Attacks.AckFlood.MinPackets == 0 {
		config.AnomalyDetection.Attacks.AckFlood.MinPackets = 1000
	}

	// 展开环境变量
	config.expandEnvVars()

	return &config
}

// expandEnvVars 展开配置中的环境变量（支持 ${VAR_NAME} 格式）
func (c *Config) expandEnvVars() {
	// 展开 API Key 中的环境变量
	for i := range c.Auth.APIKeys {
		c.Auth.APIKeys[i].Key = os.ExpandEnv(c.Auth.APIKeys[i].Key)
	}
}
