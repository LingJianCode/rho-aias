package handles

import (
	"context"
	"encoding/json"
	"fmt"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
)

// ========== FailGuard / WAF / RateLimit 模块应用逻辑 ==========

func (h *ConfigHandle) applyFailGuardConfig(raw json.RawMessage) error {
	var req config.FailGuardRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	wasRunning := h.failguardMgr.IsRunning()

	h.failguardMgr.UpdateConfig(req.Enabled, req.MaxRetry, req.FindTime, req.BanDuration, req.Mode)

	if !wasRunning && req.Enabled {
		tryStart(h.failguardMgr.Start, "[ConfigAPI] FailGuard")
	} else if wasRunning && !req.Enabled {
		h.failguardMgr.Stop()
		logger.Info("[ConfigAPI] FailGuard stopped")
	}
	return nil
}

func (h *ConfigHandle) applyWAFConfig(raw json.RawMessage) error {
	var req config.WAFRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	wasRunning := h.wafMgr.IsRunning()

	h.wafMgr.UpdateConfig(req.Enabled, req.BanDuration)

	if !wasRunning && req.Enabled {
		tryStart(h.wafMgr.Start, "[ConfigAPI] WAF")
	} else if wasRunning && !req.Enabled {
		h.wafMgr.Stop()
		logger.Info("[ConfigAPI] WAF stopped")
	}
	return nil
}

func (h *ConfigHandle) applyRateLimitConfig(raw json.RawMessage) error {
	var req config.RateLimitRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	wasRunning := h.rateLimitMgr.IsRunning()

	h.rateLimitMgr.UpdateConfig(req.Enabled, req.BanDuration)

	if !wasRunning && req.Enabled {
		tryStart(h.rateLimitMgr.Start, "[ConfigAPI] RateLimit")
	} else if wasRunning && !req.Enabled {
		h.rateLimitMgr.Stop()
		logger.Info("[ConfigAPI] RateLimit stopped")
	}
	return nil
}

// ========== AnomalyDetection 模块应用逻辑 ==========

func (h *ConfigHandle) applyAnomalyDetectionConfig(raw json.RawMessage) error {
	var req config.AnomalyDetectionRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	wasRunning := h.anomalyDetector.IsRunning()

	cfg := anomaly.AnomalyDetectionConfig{
		Enabled:         req.Enabled,
		SampleRate:      h.anomalyDetector.GetRawConfig().SampleRate,
		CheckInterval:   h.anomalyDetector.GetRawConfig().CheckInterval,
		MinPackets:      req.MinPackets,
		CleanupInterval: h.anomalyDetector.GetRawConfig().CleanupInterval,
		Ports:           req.Ports,
		Baseline: anomaly.BaselineConfig{
			MinSampleCount: req.Baseline.MinSampleCount,
			IQRMultiplier:  req.Baseline.IQRMultiplier,
			MinThreshold:   req.Baseline.MinThreshold,
			MaxAge:         req.Baseline.MaxAge,
			BlockDuration:  req.Baseline.BlockDuration,
		},
		Attacks: anomaly.AttacksConfig{
			SynFlood: anomaly.AttackConfig{Enabled: req.Attacks.SynFlood.Enabled, RatioThreshold: req.Attacks.SynFlood.RatioThreshold, BlockDuration: req.Attacks.SynFlood.BlockDuration, MinPackets: req.Attacks.SynFlood.MinPackets},
			UdpFlood: anomaly.AttackConfig{Enabled: req.Attacks.UdpFlood.Enabled, RatioThreshold: req.Attacks.UdpFlood.RatioThreshold, BlockDuration: req.Attacks.UdpFlood.BlockDuration, MinPackets: req.Attacks.UdpFlood.MinPackets},
			IcmpFlood: anomaly.AttackConfig{Enabled: req.Attacks.IcmpFlood.Enabled, RatioThreshold: req.Attacks.IcmpFlood.RatioThreshold, BlockDuration: req.Attacks.IcmpFlood.BlockDuration, MinPackets: req.Attacks.IcmpFlood.MinPackets},
			AckFlood: anomaly.AttackConfig{Enabled: req.Attacks.AckFlood.Enabled, RatioThreshold: req.Attacks.AckFlood.RatioThreshold, BlockDuration: req.Attacks.AckFlood.BlockDuration, MinPackets: req.Attacks.AckFlood.MinPackets},
		},
	}

	h.anomalyDetector.UpdateConfig(cfg)

	if !wasRunning && cfg.Enabled && h.anomalyController != nil {
		if err := h.anomalyController.SetAnomalyConfig(true, uint32(cfg.SampleRate)); err != nil {
			logger.Warnf("[ConfigAPI] Failed to set eBPF anomaly config: %v", err)
		}
		ports := make([]uint32, len(cfg.Ports))
		for i, p := range cfg.Ports {
			ports[i] = uint32(p)
		}
		if err := h.anomalyController.SetAnomalyPortFilter(len(ports) > 0, ports); err != nil {
			logger.Warnf("[ConfigAPI] Failed to set eBPF anomaly port filter: %v", err)
		}

		anomalyCtx, cancel := context.WithCancel(context.Background())
		h.anomalyMonitorCancel = cancel

		go h.anomalyController.MonitorAnomalyEvents(h.anomalyRecordPacketFn, anomalyCtx.Done())

		if err := h.anomalyDetector.Start(); err != nil {
			cancel()
			logger.Warnf("[ConfigAPI] AnomalyDetection start failed: %v", err)
		} else {
			logger.Info("[ConfigAPI] AnomalyDetection started (eBPF pipeline activated)")
		}
	} else if wasRunning && !cfg.Enabled && h.anomalyController != nil {
		if h.anomalyMonitorCancel != nil {
			h.anomalyMonitorCancel()
			h.anomalyMonitorCancel = nil
		}
		if err := h.anomalyController.SetAnomalyConfig(false, 0); err != nil {
			logger.Warnf("[ConfigAPI] Failed to disable eBPF anomaly config: %v", err)
		}
		h.anomalyDetector.Stop()
		logger.Info("[ConfigAPI] AnomalyDetection stopped (eBPF pipeline deactivated)")
	} else if !wasRunning && cfg.Enabled && h.anomalyController == nil {
		if err := h.anomalyDetector.Start(); err != nil {
			logger.Warnf("[ConfigAPI] AnomalyDetection start failed (no eBPF controller): %v", err)
		} else {
			logger.Warnf("[ConfigAPI] AnomalyDetection started without eBPF controller")
		}
	}
	return nil
}

// ========== Geo / Intel / BlocklogEvents 模块应用逻辑 ==========

func (h *ConfigHandle) applyGeoBlockingConfig(raw json.RawMessage) error {
	if h.geoBlockingMgr == nil {
		return fmt.Errorf("geo_blocking module is not initialized")
	}
	var req config.GeoBlockingRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}
	if err := h.geoBlockingMgr.UpdateConfig(req.Enabled, req.Mode, req.AllowedCountries); err != nil {
		return fmt.Errorf("failed to update geoblocking base config: %w", err)
	}

	for sourceID, srcCfg := range req.Sources {
		if err := h.geoBlockingMgr.UpdateSourceConfig(sourceID, srcCfg.Enabled, srcCfg.Periodic, srcCfg.Schedule, srcCfg.URL); err != nil {
			logger.Warnf("[ConfigAPI] Failed to update geo source %s: %v", sourceID, err)
		}
	}
	return nil
}

func (h *ConfigHandle) applyIntelConfig(raw json.RawMessage) error {
	if h.intelMgr == nil {
		return fmt.Errorf("intel module is not initialized")
	}
	var req config.IntelRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}
	h.intelMgr.UpdateConfig(req.Enabled)

	for sourceID, srcCfg := range req.Sources {
		if err := h.intelMgr.UpdateSourceConfig(sourceID, srcCfg.Enabled, srcCfg.Schedule, srcCfg.URL); err != nil {
			logger.Warnf("[ConfigAPI] Failed to update intel source %s: %v", sourceID, err)
		}
	}
	return nil
}

func (h *ConfigHandle) applyBlocklogEventsConfig(raw json.RawMessage) error {
	if h.xdp == nil {
		return fmt.Errorf("blocklog_events module is not initialized (XDP not available)")
	}

	var req config.BlocklogEventsRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	sampleRate := req.SampleRate
	if sampleRate == 0 {
		sampleRate = 1
	}

	if err := h.xdp.SetBlocklogEventConfig(req.Enabled, sampleRate); err != nil {
		return fmt.Errorf("failed to set blocklog event config: %w", err)
	}
	logger.Infof("[ConfigAPI] Blocklog Events config updated: enabled=%v, sample_rate=%d", req.Enabled, sampleRate)
	return nil
}

// ========== EgressLimit 模块应用逻辑 ==========

func (h *ConfigHandle) applyEgressLimitConfig(raw json.RawMessage) error {
	if h.tcEgress == nil {
		return fmt.Errorf("egress_limit module is not initialized (TcEgress not available)")
	}

	var req config.EgressLimitRuntime
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	// Mbps -> Bytes/s (除以 8)
	rateBytes := uint64(req.RateMbps * 1000000 / 8)

	egressCfg := ebpfs.EgressLimitConfig{
		Enabled:    0,
		RateBytes:  rateBytes,
		BurstBytes: req.BurstBytes,
	}
	if req.Enabled {
		egressCfg.Enabled = 1
	}

	if err := h.tcEgress.SetEgressLimitConfig(egressCfg); err != nil {
		return fmt.Errorf("failed to set egress limit config: %w", err)
	}

	// 设置丢包日志配置
	sampleRate := req.DropLogSampleRate
	if sampleRate == 0 {
		sampleRate = 100
	}
	if err := h.tcEgress.SetDropLogConfig(req.DropLogEnabled, sampleRate); err != nil {
		logger.Warnf("[ConfigAPI] Failed to set drop log config: %v", err)
	}

	logger.Infof("[ConfigAPI] Egress Limit config updated: enabled=%v, rate=%.1f Mbps, burst=%d bytes, drop_log=%v, drop_sample_rate=%d",
		req.Enabled, req.RateMbps, req.BurstBytes, req.DropLogEnabled, sampleRate)
	return nil
}

// ========== 辅助函数 ==========

func tryStart(startFn func() error, prefix string) {
	if err := startFn(); err != nil {
		logger.Warnf("%s start failed: %v", prefix, err)
	} else {
		logger.Info(prefix + " started")
	}
}

func getXDPEventsRuntimeConfig(xdp *ebpfs.Xdp) map[string]interface{} {
	if xdp == nil {
		return nil
	}
	config, err := xdp.GetBlocklogEventConfig()
	if err != nil {
		config = ebpfs.DefaultBlocklogEventConfig()
	}
	return map[string]interface{}{
		"enabled":     config.Enabled == 1,
		"sample_rate": config.SampleRate,
	}
}

func (h *ConfigHandle) getXDPEventsRuntimeConfig() map[string]interface{} {
	return getXDPEventsRuntimeConfig(h.xdp)
}
