package geoblocking

import (
	"errors"
	"time"
)

// SourceID GeoIP 数据源标识符
type SourceID string

const (
	SourceMaxMind SourceID = "maxmind" // MaxMind GeoIP2
	SourceDBIP    SourceID = "dbip"    // DB-IP
)

// GeoIPData GeoIP 数据结构（仅 IPv4）
type GeoIPData struct {
	IPv4CIDR  []string  // 格式: "1.0.0.0/24,CN"
	Timestamp time.Time
	Source    SourceID
}

// TotalCount 返回总规则数量
func (d *GeoIPData) TotalCount() int {
	return len(d.IPv4CIDR)
}

// CacheData 持久化缓存数据结构
type CacheData struct {
	Version   uint32
	Timestamp int64
	Config    GeoConfig
	Sources   map[SourceID]GeoIPData
}

// GeoConfig 地域封禁配置
type GeoConfig struct {
	Enabled          bool
	Mode             string
	AllowedCountries []string
}

// Validate 验证配置
func (c *GeoConfig) Validate() error {
	if c.Enabled && c.Mode == "whitelist" && len(c.AllowedCountries) == 0 {
		return errors.New("whitelist mode requires allowed_countries")
	}
	return nil
}

// Status 地域封禁模块状态
type Status struct {
	Enabled          bool                      // 实际是否在过滤（数据已加载并激活）
	Mode             string                    // 模式 (whitelist/blacklist)
	AllowedCountries []string                  // 允许的国家列表
	LastUpdate       time.Time                 // 最后更新时间
	TotalRules       int                       // 总规则数量
	Sources          map[SourceID]SourceStatus // 各数据源状态
}

// SourceStatus 单个 GeoIP 数据源的状态
type SourceStatus struct {
	Enabled    bool      // 是否启用
	LastUpdate time.Time // 最后更新时间
	Success    bool      // 最后一次更新是否成功
	RuleCount  int       // 该数据源的规则数量
	Error      string    // 错误信息
}

var ErrGeoIPCacheNotFound = errors.New("geoip cache not found")

// NewCacheData 创建新的缓存数据
func NewCacheData() *CacheData {
	return &CacheData{
		Version: 1,
		Sources: make(map[SourceID]GeoIPData),
	}
}

// NewGeoIPData 创建新的 GeoIP 数据
func NewGeoIPData(source SourceID) *GeoIPData {
	return &GeoIPData{
		IPv4CIDR:  make([]string, 0),
		Timestamp: time.Now(),
		Source:    source,
	}
}

// AddCIDR 添加 CIDR 规则
func (d *GeoIPData) AddCIDR(cidr string) {
	d.IPv4CIDR = append(d.IPv4CIDR, cidr)
}

// AddCIDRs 批量添加 CIDR 规则
func (d *GeoIPData) AddCIDRs(cidrs []string) {
	d.IPv4CIDR = append(d.IPv4CIDR, cidrs...)
}
