package models

// BlocklogRecord 阻断日志明细记录（按天分表：blocklog_YYYYMMDD）
type BlocklogRecord struct {
	ID          uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Hour        int    `gorm:"index" json:"hour"`                  // 0-23，支持跨小时范围查询
	Timestamp   int64  `gorm:"index" json:"timestamp"`             // Unix 纳秒
	SrcIP       string `gorm:"size:45;index" json:"src_ip"`        // 源 IP 地址
	DstIP       string `gorm:"size:45" json:"dst_ip"`              // 目标 IP 地址
	DstPort     uint16 `json:"dst_port"`                           // 目标端口 (TCP/UDP)
	MatchType   string `gorm:"size:20;index" json:"match_type"`    // 匹配类型
	RuleSource  string `gorm:"size:20;index" json:"rule_source"`   // 规则来源
	CountryCode string `gorm:"size:5" json:"country_code"`         // 国家代码
	PacketSize  uint32 `json:"packet_size"`                        // 数据包大小
}

// TableName 返回默认表名（实际使用 blocklog_YYYYMMDD 动态表名）
func (BlocklogRecord) TableName() string { return "blocklog_records" }
