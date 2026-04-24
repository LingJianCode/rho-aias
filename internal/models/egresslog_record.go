package models

// EgresslogRecord Egress 丢包日志明细记录（按天分表：egresslog_YYYYMMDD）
type EgresslogRecord struct {
	ID        uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Hour      int    `gorm:"index" json:"hour"`                  // 0-23，支持跨小时范围查询
	Timestamp int64  `gorm:"index" json:"timestamp"`             // Unix 纳秒
	DstIP     string `gorm:"size:45;index" json:"dst_ip"`        // 目标 IP 地址
	PktLen    uint32 `json:"pkt_len"`                            // 被丢弃的包大小 (Bytes)
	Tokens    uint64 `json:"tokens"`                             // 丢包时令牌数 (诊断用)
	RateBytes uint64 `json:"rate_bytes"`                         // 当时限速速率 (诊断用)
}

// TableName 返回默认表名（实际使用 egresslog_YYYYMMDD 动态表名）
func (EgresslogRecord) TableName() string { return "egresslog_records" }
