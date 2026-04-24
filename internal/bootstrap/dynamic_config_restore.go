package bootstrap

import (
	"fmt"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/services"
)

// loadDynamicConfigFromDB 从数据库加载动态配置覆盖 YAML 值
// 只在启动时调用一次，之后运行时全走 API
func loadDynamicConfigFromDB(svc *services.DynamicConfigService, cfg *config.Config) {
	loaded := make(map[string]string)

	var fg config.FailGuardRuntime
	if ok, err := svc.LoadTo("failguard", &fg); err != nil {
		logger.Warnf("[Main] Failed to load failguard dynamic config from DB: %v", err)
	} else if ok {
		cfg.FailGuard.Enabled = fg.Enabled
		cfg.FailGuard.MaxRetry = fg.MaxRetry
		cfg.FailGuard.FindTime = fg.FindTime
		cfg.FailGuard.BanDuration = fg.BanDuration
		cfg.FailGuard.Mode = fg.Mode
		loaded["failguard"] = fmt.Sprintf("enabled=%v, max_retry=%d, find_time=%d, ban_duration=%d, mode=%s",
			fg.Enabled, fg.MaxRetry, fg.FindTime, fg.BanDuration, fg.Mode)
	}

	var wf config.WAFRuntime
	if ok, err := svc.LoadTo("waf", &wf); err != nil {
		logger.Warnf("[Main] Failed to load waf dynamic config from DB: %v", err)
	} else if ok {
		cfg.WAF.Enabled = wf.Enabled
		cfg.WAF.BanDuration = wf.BanDuration
		loaded["waf"] = fmt.Sprintf("enabled=%v, ban_duration=%d", wf.Enabled, wf.BanDuration)
	}

	var rl config.RateLimitRuntime
	if ok, err := svc.LoadTo("rate_limit", &rl); err != nil {
		logger.Warnf("[Main] Failed to load rate_limit dynamic config from DB: %v", err)
	} else if ok {
		cfg.RateLimit.Enabled = rl.Enabled
		cfg.RateLimit.BanDuration = rl.BanDuration
		loaded["rate_limit"] = fmt.Sprintf("enabled=%v, ban_duration=%d", rl.Enabled, rl.BanDuration)
	}

	var ad config.AnomalyDetectionRuntime
	if ok, err := svc.LoadTo("anomaly_detection", &ad); err != nil {
		logger.Warnf("[Main] Failed to load anomaly_detection dynamic config from DB: %v", err)
	} else if ok {
		cfg.AnomalyDetection.Enabled = ad.Enabled
		cfg.AnomalyDetection.MinPackets = ad.MinPackets
		cfg.AnomalyDetection.Ports = ad.Ports
		cfg.AnomalyDetection.Baseline = config.BaselineConfig{
			MinSampleCount: ad.Baseline.MinSampleCount,
			IQRMultiplier:  ad.Baseline.IQRMultiplier,
			MinThreshold:   ad.Baseline.MinThreshold,
			MaxAge:         ad.Baseline.MaxAge,
			BlockDuration:  ad.Baseline.BlockDuration,
		}
		cfg.AnomalyDetection.Attacks = config.AttacksConfig{
			SynFlood:  config.AttackConfig{Enabled: ad.Attacks.SynFlood.Enabled, RatioThreshold: ad.Attacks.SynFlood.RatioThreshold, BlockDuration: ad.Attacks.SynFlood.BlockDuration, MinPackets: ad.Attacks.SynFlood.MinPackets},
			UdpFlood:  config.AttackConfig{Enabled: ad.Attacks.UdpFlood.Enabled, RatioThreshold: ad.Attacks.UdpFlood.RatioThreshold, BlockDuration: ad.Attacks.UdpFlood.BlockDuration, MinPackets: ad.Attacks.UdpFlood.MinPackets},
			IcmpFlood: config.AttackConfig{Enabled: ad.Attacks.IcmpFlood.Enabled, RatioThreshold: ad.Attacks.IcmpFlood.RatioThreshold, BlockDuration: ad.Attacks.IcmpFlood.BlockDuration, MinPackets: ad.Attacks.IcmpFlood.MinPackets},
			AckFlood:  config.AttackConfig{Enabled: ad.Attacks.AckFlood.Enabled, RatioThreshold: ad.Attacks.AckFlood.RatioThreshold, BlockDuration: ad.Attacks.AckFlood.BlockDuration, MinPackets: ad.Attacks.AckFlood.MinPackets},
		}
		loaded["anomaly_detection"] = fmt.Sprintf("enabled=%v, min_packets=%d, ports=%v",
			ad.Enabled, ad.MinPackets, ad.Ports)
	}

	var geo config.GeoBlockingRuntime
	if ok, err := svc.LoadTo("geo_blocking", &geo); err != nil {
		logger.Warnf("[Main] Failed to load geo_blocking dynamic config from DB: %v", err)
	} else if ok {
		cfg.GeoBlocking.Enabled = geo.Enabled
		cfg.GeoBlocking.Mode = geo.Mode
		cfg.GeoBlocking.AllowedCountries = geo.AllowedCountries
		if len(geo.Sources) > 0 {
			converted := make(map[string]config.GeoIPSource, len(geo.Sources))
			for sid, src := range geo.Sources {
				existingFormat := ""
				if existing, exists := cfg.GeoBlocking.Sources[sid]; exists {
					existingFormat = existing.Format
				}
				converted[sid] = config.GeoIPSource{
					Enabled:  src.Enabled,
					Periodic: src.Periodic,
					Schedule: src.Schedule,
					URL:      src.URL,
					Format:   existingFormat,
				}
			}
			cfg.GeoBlocking.Sources = converted
		}
		loaded["geo_blocking"] = fmt.Sprintf("enabled=%v, mode=%s, countries=%v, sources=%d",
			geo.Enabled, geo.Mode, geo.AllowedCountries, len(geo.Sources))
	}

	var intel config.IntelRuntime
	if ok, err := svc.LoadTo("intel", &intel); err != nil {
		logger.Warnf("[Main] Failed to load intel dynamic config from DB: %v", err)
	} else if ok {
		cfg.Intel.Enabled = intel.Enabled
		if len(intel.Sources) > 0 {
			converted := make(map[string]config.IntelSource, len(intel.Sources))
			for sid, src := range intel.Sources {
				existing := cfg.Intel.Sources[sid]
				converted[sid] = config.IntelSource{
					Enabled:  src.Enabled,
					Periodic: existing.Periodic,
					Schedule: src.Schedule,
					URL:      src.URL,
					Format:   existing.Format,
				}
			}
			cfg.Intel.Sources = converted
		}
		loaded["intel"] = fmt.Sprintf("enabled=%v, sources=%d", intel.Enabled, len(intel.Sources))
	}

	var blocklogEvents config.BlocklogEventsRuntime
	if ok, err := svc.LoadTo("blocklog_events", &blocklogEvents); err != nil {
		logger.Warnf("[Main] Failed to load blocklog_events dynamic config from DB: %v", err)
	} else if ok {
		// blocklog_events 的配置不在 cfg 中（直接操作 eBPF map），
		// 存入 cfg.BlockLog 的扩展字段供 LoadCachedRules 恢复
		cfg.BlockLog.EventsEnabled = blocklogEvents.Enabled
		cfg.BlockLog.EventsSampleRate = blocklogEvents.SampleRate
		loaded["blocklog_events"] = fmt.Sprintf("enabled=%v, sample_rate=%d", blocklogEvents.Enabled, blocklogEvents.SampleRate)
	}

	var egressLimit config.EgressLimitRuntime
	if ok, err := svc.LoadTo("egress_limit", &egressLimit); err != nil {
		logger.Warnf("[Main] Failed to load egress_limit dynamic config from DB: %v", err)
	} else if ok {
		cfg.EgressLimit.Enabled = egressLimit.Enabled
		cfg.EgressLimit.RateMbps = egressLimit.RateMbps
		cfg.EgressLimit.BurstBytes = egressLimit.BurstBytes
		cfg.EgressLimit.DropLogEnabled = egressLimit.DropLogEnabled
		cfg.EgressLimit.DropLogSampleRate = egressLimit.DropLogSampleRate
		// 写入运行时扩展字段，供 LoadCachedRules 恢复 eBPF 丢包日志配置
		cfg.EgressLimit.DropLogEnabledRuntime = egressLimit.DropLogEnabled
		cfg.EgressLimit.DropLogSampleRateRuntime = egressLimit.DropLogSampleRate
		loaded["egress_limit"] = fmt.Sprintf("enabled=%v, rate=%.1f, burst=%d, drop_log=%v, drop_sample_rate=%d",
			egressLimit.Enabled, egressLimit.RateMbps, egressLimit.BurstBytes,
			egressLimit.DropLogEnabled, egressLimit.DropLogSampleRate)
	}

	modules := []string{"failguard", "waf", "rate_limit", "anomaly_detection", "geo_blocking", "intel", "blocklog_events", "egress_limit"}
	logger.Info("[Main] Dynamic config loaded (DB values override YAML):")
	for _, mod := range modules {
		if val, exists := loaded[mod]; exists {
			logger.Infof("[Main] [DynamicConfig] %-20s → DB override       %s", mod, val)
		} else {
			logger.Infof("[Main] [DynamicConfig] %-20s → YAML default      (no DB record)", mod)
		}
	}
}
