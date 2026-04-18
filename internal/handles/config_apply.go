package handles

import (
	"context"
	"encoding/json"
	"fmt"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
)

// ========== 请求结构体 ==========

type failGuardConfigRequest struct {
	Enabled     *bool  `json:"enabled" validate:"omitempty"`
	MaxRetry    *int   `json:"max_retry" validate:"omitempty,gte=1,lte=1000"`
	FindTime    *int   `json:"find_time" validate:"omitempty,gte=1,lte=86400"`
	BanDuration *int   `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
	Mode        string `json:"mode" validate:"omitempty,oneof=normal ddos aggressive"`
}

type wafConfigRequest struct {
	Enabled     *bool `json:"enabled" validate:"omitempty"`
	BanDuration *int  `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
}

type rateLimitConfigRequest struct {
	Enabled     *bool `json:"enabled" validate:"omitempty"`
	BanDuration *int  `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
}

type anomalyDetectionConfigRequest struct {
	Enabled    *bool                   `json:"enabled" validate:"omitempty"`
	MinPackets *int                    `json:"min_packets" validate:"omitempty,gte=1,lte=100000"`
	Ports      []int                   `json:"ports" validate:"omitempty,dive,gte=1,lte=65535"`
	Baseline   *anomaly.BaselineConfig `json:"baseline" validate:"omitempty"`
	Attacks    *anomaly.AttacksConfig  `json:"attacks" validate:"omitempty"`
}

type geoBlockingConfigRequest struct {
	Enabled          *bool                      `json:"enabled" validate:"omitempty"`
	Mode             string                     `json:"mode" validate:"omitempty,oneof=whitelist blacklist"`
	AllowedCountries []string                   `json:"allowed_countries" validate:"omitempty,dive,len=2"`
	Sources          map[string]geoSourceConfig `json:"sources" validate:"omitempty"`
}

type geoSourceConfig struct {
	Enabled  *bool  `json:"enabled" validate:"omitempty"`
	Periodic *bool  `json:"periodic" validate:"omitempty"`
	Schedule string `json:"schedule" validate:"omitempty"`
	URL      string `json:"url" validate:"omitempty"`
}

type intelConfigRequest struct {
	Enabled *bool                        `json:"enabled"`
	Sources map[string]intelSourceConfig `json:"sources"`
}

type intelSourceConfig struct {
	Enabled  *bool  `json:"enabled"`
	Schedule string `json:"schedule"`
	URL      string `json:"url"`
}

// xdpEventsConfigRequest XDP 事件上报配置请求
type xdpEventsConfigRequest struct {
	Enabled    *bool   `json:"enabled" validate:"omitempty"`
	SampleRate *uint32 `json:"sample_rate" validate:"omitempty,gte=1"`
}

// ========== FailGuard / WAF / RateLimit 模块应用逻辑 ==========

func (h *ConfigHandle) applyFailGuardConfig(raw json.RawMessage) error {
	var req failGuardConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	current := h.failguardMonitor.GetConfig()
	wasRunning := h.failguardMonitor.IsRunning()

	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	maxRetry := intValue(mapInt(current, "max_retry", 0), req.MaxRetry)
	findTime := intValue(mapInt(current, "find_time", 0), req.FindTime)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)
	mode := req.Mode
	if mode == "" {
		mode = mapString(current, "mode", "")
	}

	h.failguardMonitor.UpdateConfig(enabled, maxRetry, findTime, banDuration, mode)

	if !wasRunning && enabled {
		tryStart(h.failguardMonitor.Start, "[ConfigAPI] FailGuard")
	} else if wasRunning && !enabled {
		h.failguardMonitor.Stop()
		logger.Info("[ConfigAPI] FailGuard stopped")
	}
	return nil
}

func (h *ConfigHandle) applyWAFConfig(raw json.RawMessage) error {
	var req wafConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	current := h.wafMonitor.GetConfig()
	wasRunning := h.wafMonitor.IsRunning()

	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)
	h.wafMonitor.UpdateConfig(enabled, banDuration)

	if !wasRunning && enabled {
		tryStart(h.wafMonitor.Start, "[ConfigAPI] WAF")
	} else if wasRunning && !enabled {
		h.wafMonitor.Stop()
		logger.Info("[ConfigAPI] WAF stopped")
	}
	return nil
}

func (h *ConfigHandle) applyRateLimitConfig(raw json.RawMessage) error {
	var req rateLimitConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	current := h.rateLimitMonitor.GetConfig()
	wasRunning := h.rateLimitMonitor.IsRunning()

	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)
	h.rateLimitMonitor.UpdateConfig(enabled, banDuration)

	if !wasRunning && enabled {
		tryStart(h.rateLimitMonitor.Start, "[ConfigAPI] RateLimit")
	} else if wasRunning && !enabled {
		h.rateLimitMonitor.Stop()
		logger.Info("[ConfigAPI] RateLimit stopped")
	}
	return nil
}

// ========== AnomalyDetection 模块应用逻辑 ==========

func (h *ConfigHandle) applyAnomalyDetectionConfig(raw json.RawMessage) error {
	var req anomalyDetectionConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	rawCfg := h.anomalyDetector.GetRawConfig()
	wasRunning := h.anomalyDetector.IsRunning()

	cfg := anomaly.AnomalyDetectionConfig{
		Enabled:         boolValue(rawCfg.Enabled, req.Enabled),
		SampleRate:      rawCfg.SampleRate,
		CheckInterval:   rawCfg.CheckInterval,
		MinPackets:      intValue(rawCfg.MinPackets, req.MinPackets),
		CleanupInterval: rawCfg.CleanupInterval,
		Baseline:        baselineValue(rawCfg.Baseline, req.Baseline),
		Attacks:         attacksValue(rawCfg.Attacks, req.Attacks),
	}
	if req.Ports != nil {
		cfg.Ports = req.Ports
	} else {
		cfg.Ports = rawCfg.Ports
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

		// 创建带取消的 context，用于后续可主动停止该 goroutine
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
		// 停止旧的 anomaly monitor goroutine 防止泄漏
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

// ========== Geo / Intel / XDP Events 模块应用逻辑 ==========

func (h *ConfigHandle) applyGeoBlockingConfig(raw json.RawMessage) error {
	if h.geoBlockingMgr == nil || isNilInterface(h.geoBlockingMgr) {
		return fmt.Errorf("geo_blocking module is not initialized")
	}
	var req geoBlockingConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}
	current := h.geoBlockingMgr.GetConfig()
	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	mode := req.Mode
	if mode == "" {
		mode = mapString(current, "mode", "")
	}
	countries := req.AllowedCountries
	if countries == nil {
		countries = mapStringSlice(current, "allowed_countries")
	}
	if err := h.geoBlockingMgr.UpdateConfig(enabled, mode, countries); err != nil {
		return fmt.Errorf("failed to update geoblocking base config: %w", err)
	}

	// 处理单源配置更新
	for sourceID, srcCfg := range req.Sources {
		currentSrcMap, _ := current["sources"].(map[string]interface{})
		defaultEnabled := true
		defaultPeriodic := true
		if srcMap, ok := currentSrcMap[sourceID]; ok {
			if src, ok2 := srcMap.(map[string]interface{}); ok2 {
				defaultEnabled = mapBool(src, "enabled", true)
				defaultPeriodic = mapBool(src, "periodic", true)
			}
		}
		srcEnabled := boolValue(defaultEnabled, srcCfg.Enabled)
		srcPeriodic := boolValue(defaultPeriodic, srcCfg.Periodic)
		if err := h.geoBlockingMgr.UpdateSourceConfig(sourceID, srcEnabled, srcPeriodic, srcCfg.Schedule, srcCfg.URL); err != nil {
			logger.Warnf("[ConfigAPI] Failed to update geo source %s: %v", sourceID, err)
		}
	}
	return nil
}

func (h *ConfigHandle) applyIntelConfig(raw json.RawMessage) error {
	if h.intelMgr == nil || isNilInterface(h.intelMgr) {
		return fmt.Errorf("intel module is not initialized")
	}
	var req intelConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}
	if req.Enabled != nil {
		h.intelMgr.UpdateConfig(*req.Enabled)
	}

	currentIntel := h.intelMgr.GetConfig()
	for sourceID, srcCfg := range req.Sources {
		currentSrcMap, _ := currentIntel["sources"].(map[string]interface{})
		defaultEnabled := true
		if srcMap, ok := currentSrcMap[sourceID]; ok {
			if src, ok2 := srcMap.(map[string]interface{}); ok2 {
				defaultEnabled = mapBool(src, "enabled", true)
			}
		}
		enabled := boolValue(defaultEnabled, srcCfg.Enabled)
		if err := h.intelMgr.UpdateSourceConfig(sourceID, enabled, srcCfg.Schedule, srcCfg.URL); err != nil {
			logger.Warnf("[ConfigAPI] Failed to update intel source %s: %v", sourceID, err)
		}
	}
	return nil
}

func (h *ConfigHandle) applyXDPEventsConfig(raw json.RawMessage) error {
	if h.xdp == nil {
		return fmt.Errorf("xdp_events module is not initialized (XDP not available)")
	}

	var req xdpEventsConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	currentCfg, _ := h.xdp.GetBlocklogEventConfig()
	enabled := currentCfg.Enabled == 1
	sampleRate := currentCfg.SampleRate
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.SampleRate != nil {
		sampleRate = *req.SampleRate
		if sampleRate == 0 {
			sampleRate = 1
		}
	}

	if err := h.xdp.SetBlocklogEventConfig(enabled, sampleRate); err != nil {
		return fmt.Errorf("failed to set xdp event config: %w", err)
	}
	logger.Infof("[ConfigAPI] XDP Blocklog Events config updated: enabled=%v, sample_rate=%d", enabled, sampleRate)
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
