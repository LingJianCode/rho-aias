package ebpfs

// ============================================
// BlocklogEvent Reporting 相关方法
// ============================================

// SetBlocklogEventConfig 设置事件上报配置
func (x *Xdp) SetBlocklogEventConfig(enabled bool, sampleRate uint32) error {
	config := NewBlocklogEventConfig(enabled, sampleRate)
	key := uint32(0)
	return x.objects.BlocklogEventConfig.Put(&key, &config)
}

// GetBlocklogEventConfig 获取当前事件上报配置
func (x *Xdp) GetBlocklogEventConfig() (BlocklogEventConfig, error) {
	key := uint32(0)
	config := BlocklogEventConfig{}
	if err := x.objects.BlocklogEventConfig.Lookup(&key, &config); err != nil {
		return DefaultBlocklogEventConfig(), err
	}
	return config, nil
}

// IsBlocklogEventReportingEnabled 检查事件上报是否启用
func (x *Xdp) IsBlocklogEventReportingEnabled() bool {
	config, err := x.GetBlocklogEventConfig()
	if err != nil {
		return false
	}
	return config.Enabled == 1
}
