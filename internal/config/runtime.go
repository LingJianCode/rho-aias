package config

// ============================================================
// Runtime 配置结构体（全量，值类型）
// 用于: API 请求反序列化 + 校验 / DB 存取 / 启动恢复
// 单一数据源，消除 handles 和 bootstrap 中的重复定义
// ============================================================

// --- FailGuard ---

type FailGuardRuntime struct {
	Enabled     bool   `json:"enabled" yaml:"enabled" validate:"required"`
	MaxRetry    int    `json:"max_retry" yaml:"max_retry" validate:"gte=1,lte=1000"`
	FindTime    int    `json:"find_time" yaml:"find_time" validate:"gte=1,lte=86400"`
	BanDuration int    `json:"ban_duration" yaml:"ban_duration" validate:"gte=1,lte=31536000"`
	Mode        string `json:"mode" yaml:"mode" validate:"oneof=normal ddos aggressive"`
}

// --- WAF ---

type WAFRuntime struct {
	Enabled     bool `json:"enabled" yaml:"enabled" validate:"required"`
	BanDuration int  `json:"ban_duration" yaml:"ban_duration" validate:"gte=1,lte=31536000"`
}

// --- RateLimit ---

type RateLimitRuntime struct {
	Enabled     bool `json:"enabled" yaml:"enabled" validate:"required"`
	BanDuration int  `json:"ban_duration" yaml:"ban_duration" validate:"gte=1,lte=31536000"`
}

// --- AnomalyDetection ---

type AnomalyDetectionRuntime struct {
	Enabled    bool            `json:"enabled" yaml:"enabled" validate:"required"`
	MinPackets int             `json:"min_packets" yaml:"min_packets" validate:"gte=1,lte=100000"`
	Ports      []int           `json:"ports" yaml:"ports" validate:"required,dive,gte=1,lte=65535"`
	Baseline   BaselineRuntime `json:"baseline" yaml:"baseline"`
	Attacks    AttacksRuntime  `json:"attacks" yaml:"attacks"`
}

type BaselineRuntime struct {
	MinSampleCount int     `json:"min_sample_count" yaml:"min_sample_count" validate:"gte=1,lte=1000000"`
	IQRMultiplier  float64 `json:"iqr_multiplier" yaml:"iqr_multiplier" validate:"gte=1,lte=10"`
	MinThreshold   int     `json:"min_threshold" yaml:"min_threshold" validate:"gte=1,lte=10000000"`
	MaxAge         int     `json:"max_age" yaml:"max_age" validate:"gte=60,lte=604800"`
	BlockDuration  int     `json:"block_duration" yaml:"block_duration" validate:"gte=1,lte=31536000"`
}

type AttacksRuntime struct {
	SynFlood  AttackRuntime `json:"syn_flood" yaml:"syn_flood"`
	UdpFlood  AttackRuntime `json:"udp_flood" yaml:"udp_flood"`
	IcmpFlood AttackRuntime `json:"icmp_flood" yaml:"icmp_flood"`
	AckFlood  AttackRuntime `json:"ack_flood" yaml:"ack_flood"`
}

type AttackRuntime struct {
	Enabled        bool    `json:"enabled" yaml:"enabled"`
	RatioThreshold float64 `json:"ratio_threshold" yaml:"ratio_threshold" validate:"gte=0,lte=1"`
	BlockDuration  int     `json:"block_duration" yaml:"block_duration" validate:"gte=1,lte=31536000"`
	MinPackets     int     `json:"min_packets" yaml:"min_packets" validate:"gte=0,lte=1000000"`
}

// --- GeoBlocking ---

type GeoBlockingRuntime struct {
	Enabled          bool                        `json:"enabled" yaml:"enabled" validate:"required"`
	Mode             string                      `json:"mode" yaml:"mode" validate:"oneof=whitelist blacklist"`
	AllowedCountries []string                    `json:"allowed_countries" yaml:"allowed_countries" validate:"omitempty,dive,len=2"`
	Sources          map[string]GeoSourceRuntime `json:"sources,omitempty" yaml:"sources"`
}

type GeoSourceRuntime struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Periodic bool   `json:"periodic" yaml:"periodic"`
	Schedule string `json:"schedule" yaml:"schedule"`
	URL      string `json:"url" yaml:"url"`
}

// --- Intel ---

type IntelRuntime struct {
	Enabled bool                          `json:"enabled" yaml:"enabled" validate:"required"`
	Sources map[string]IntelSourceRuntime `json:"sources,omitempty" yaml:"sources"`
}

type IntelSourceRuntime struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Schedule string `json:"schedule" yaml:"schedule"`
	URL      string `json:"url" yaml:"url"`
}

// --- BlocklogEvents ---

type BlocklogEventsRuntime struct {
	Enabled    bool   `json:"enabled" yaml:"enabled" validate:"required"`
	SampleRate uint32 `json:"sample_rate" yaml:"sample_rate" validate:"gte=1"`
}

// --- EgressLimit ---

type EgressLimitRuntime struct {
	Enabled           bool    `json:"enabled" yaml:"enabled"`
	RateMbps          float64 `json:"rate_mbps" yaml:"rate_mbps" validate:"gt=0"`
	BurstBytes        uint64  `json:"burst_bytes" yaml:"burst_bytes" validate:"gte=1"`
	DropLogEnabled    bool    `json:"drop_log_enabled" yaml:"drop_log_enabled"`
	DropLogSampleRate uint32  `json:"drop_log_sample_rate" yaml:"drop_log_sample_rate" validate:"gte=1"`
}
