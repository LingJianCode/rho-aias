package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Server      ServerConfig        `yaml:"server"`
	Ebpf        EbpfConfig          `yaml:"ebpf"`
	Intel       IntelConfig         `yaml:"intel"`
	GeoBlocking GeoBlockingConfig   `yaml:"geo_blocking"`
	Manual      ManualConfig        `yaml:"manual"`
	Auth        AuthConfig          `yaml:"auth"`
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
	Schedule string `yaml:"schedule"` // Cron 表达式 (如: "0 * * * *" 表示每小时整点)
	URL      string `yaml:"url"`      // 数据源 URL
	Format   string `yaml:"format"`   // 格式类型 (ipsum/spamhaus)
}

// GeoBlockingConfig 地域封禁配置
type GeoBlockingConfig struct {
	Enabled              bool                   `yaml:"enabled"`               // 总开关
	Mode                 string                 `yaml:"mode"`                  // "whitelist" 或 "blacklist"
	AllowedCountries     []string               `yaml:"allowed_countries"`     // 允许的国家代码列表
	AllowPrivateNetworks bool                   `yaml:"allow_private_networks"` // 允许私有网段绕过地域检查
	PersistenceDir       string                 `yaml:"persistence_dir"`       // 持久化目录
	BatchSize            int                    `yaml:"batch_size"`            // 批量更新大小
	Sources              map[string]GeoIPSource `yaml:"sources"`               // GeoIP 数据源配置
}

// GeoIPSource GeoIP 数据源配置
// 数据由外部工具下载后托管在 nginx 文件服务器
type GeoIPSource struct {
	Enabled  bool   `yaml:"enabled"`  // 是否启用
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
	Enabled         bool   `yaml:"enabled"`          // 是否启用认证
	JWTSecret       string `yaml:"jwt_secret"`       // JWT 密钥（建议从环境变量读取）
	JWTIssuer       string `yaml:"jwt_issuer"`       // JWT 签发者
	TokenDuration   int    `yaml:"token_duration"`   // Token 有效期（分钟）
	DatabasePath    string `yaml:"database_path"`    // 数据库路径
	CaptchaEnabled  bool   `yaml:"captcha_enabled"`  // 是否启用验证码
	CaptchaDuration int    `yaml:"captcha_duration"` // 验证码有效期（分钟）
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

	return &config
}
