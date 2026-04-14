package ebpfs

// ============================================
// Event Reporting 相关方法
// ============================================

// SetEventConfig 设置事件上报配置
func (x *Xdp) SetEventConfig(enabled bool, sampleRate uint32) error {
	config := NewEventConfig(enabled, sampleRate)
	key := uint32(0)
	return x.objects.EventConfig.Put(&key, &config)
}

// GetEventConfig 获取当前事件上报配置
func (x *Xdp) GetEventConfig() (EventConfig, error) {
	key := uint32(0)
	config := EventConfig{}
	if err := x.objects.EventConfig.Lookup(&key, &config); err != nil {
		return DefaultEventConfig(), err
	}
	return config, nil
}

// IsEventReportingEnabled 检查事件上报是否启用
func (x *Xdp) IsEventReportingEnabled() bool {
	config, err := x.GetEventConfig()
	if err != nil {
		return false
	}
	return config.Enabled == 1
}
