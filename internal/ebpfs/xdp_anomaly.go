package ebpfs

import "rho-aias/internal/logger"

// ============================================
// Anomaly Detection 相关方法
// ============================================

// SetAnomalyConfig 设置异常检测采样配置
func (x *Xdp) SetAnomalyConfig(enabled bool, sampleRate uint32) error {
	config := NewAnomalyConfig(enabled, sampleRate)
	key := uint32(0)
	return x.objects.AnomalyConfig.Put(&key, &config)
}

// SetAnomalyPortFilter 设置异常检测端口过滤
func (x *Xdp) SetAnomalyPortFilter(enabled bool, ports []uint32) error {
	x.mapMu.Lock()
	defer x.mapMu.Unlock()

	key := uint32(0)
	config := AnomalyConfig{}
	if err := x.objects.AnomalyConfig.Lookup(&key, &config); err != nil {
		return err
	}

	if enabled && len(ports) > 0 {
		config.PortFilterEnabled = 1
	} else {
		config.PortFilterEnabled = 0
	}
	if err := x.objects.AnomalyConfig.Put(&key, &config); err != nil {
		return err
	}

	if config.PortFilterEnabled == 0 {
		for _, oldPort := range x.anomalyPorts {
			zero := uint32(0)
			if err := x.objects.AnomalyPorts.Put(&oldPort, &zero); err != nil {
				logger.Warnf("failed to clear anomaly port: %v", err)
			}
		}
		x.anomalyPorts = nil
		logger.Info("[XDP] Anomaly port filter disabled")
		return nil
	}

	// 清除旧端口，设置新端口（ARRAY map 需要显式清零旧条目）
	for _, oldPort := range x.anomalyPorts {
		zero := uint32(0)
		if err := x.objects.AnomalyPorts.Put(&oldPort, &zero); err != nil {
			logger.Warnf("failed to clear old anomaly port: %v", err)
		}
	}

	flag := uint32(1)
	for _, port := range ports {
		if err := x.objects.AnomalyPorts.Put(&port, &flag); err != nil {
			logger.Warnf("[XDP] Failed to add anomaly port %d: %v", port, err)
		}
	}
	x.anomalyPorts = make([]uint32, len(ports))
	copy(x.anomalyPorts, ports)

	logger.Infof("[XDP] Anomaly port filter enabled, ports: %v", ports)
	return nil
}

// GetAnomalyConfig 获取当前异常检测采样配置
func (x *Xdp) GetAnomalyConfig() (AnomalyConfig, error) {
	key := uint32(0)
	config := AnomalyConfig{}
	if err := x.objects.AnomalyConfig.Lookup(&key, &config); err != nil {
		return DefaultAnomalyConfig(), err
	}
	return config, nil
}

// IsAnomalyDetectionEnabled 检查异常检测是否启用
func (x *Xdp) IsAnomalyDetectionEnabled() bool {
	config, err := x.GetAnomalyConfig()
	if err != nil {
		return false
	}
	return config.Enabled == 1
}
