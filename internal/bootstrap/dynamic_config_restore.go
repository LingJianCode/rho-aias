package bootstrap

import (
	"fmt"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/services"
)

// loadDynamicConfigFromDB 从数据库加载动态配置覆盖 YAML 值
// 只在启动时调用一次，之后运行时全走 API
func loadDynamicConfigFromDB(svc *services.DynamicConfigService, cfg *config.Config) {
	loaded := make(map[string]string)

	type failGuardDynamic struct {
		Enabled     bool   `json:"enabled"`
		MaxRetry    int    `json:"max_retry"`
		FindTime    int    `json:"find_time"`
		BanDuration int    `json:"ban_duration"`
		Mode        string `json:"mode"`
	}
	var fg failGuardDynamic
	if ok, err := svc.LoadTo("failguard", &fg); err != nil {
		logger.Warnf("[Main] Failed to load failguard dynamic config from DB: %v", err)
	} else if ok {
		cfg.FailGuard.Enabled = fg.Enabled
		if fg.MaxRetry > 0 { cfg.FailGuard.MaxRetry = fg.MaxRetry }
		if fg.FindTime > 0 { cfg.FailGuard.FindTime = fg.FindTime }
		if fg.BanDuration > 0 { cfg.FailGuard.BanDuration = fg.BanDuration }
		if fg.Mode != "" { cfg.FailGuard.Mode = fg.Mode }
		loaded["failguard"] = fmt.Sprintf("enabled=%v, max_retry=%d, find_time=%d, ban_duration=%d, mode=%s",
			fg.Enabled, fg.MaxRetry, fg.FindTime, fg.BanDuration, fg.Mode)
	}

	type wafDynamic struct {
		Enabled     bool `json:"enabled"`
		BanDuration int  `json:"ban_duration"`
	}
	var wf wafDynamic
	if ok, err := svc.LoadTo("waf", &wf); err != nil {
		logger.Warnf("[Main] Failed to load waf dynamic config from DB: %v", err)
	} else if ok {
		cfg.WAF.Enabled = wf.Enabled
		if wf.BanDuration > 0 { cfg.WAF.BanDuration = wf.BanDuration }
		loaded["waf"] = fmt.Sprintf("enabled=%v, ban_duration=%d", wf.Enabled, wf.BanDuration)
	}

	type rateLimitDynamic struct {
		Enabled     bool `json:"enabled"`
		BanDuration int  `json:"ban_duration"`
	}
	var rl rateLimitDynamic
	if ok, err := svc.LoadTo("rate_limit", &rl); err != nil {
		logger.Warnf("[Main] Failed to load rate_limit dynamic config from DB: %v", err)
	} else if ok {
		cfg.RateLimit.Enabled = rl.Enabled
		if rl.BanDuration > 0 { cfg.RateLimit.BanDuration = rl.BanDuration }
		loaded["rate_limit"] = fmt.Sprintf("enabled=%v, ban_duration=%d", rl.Enabled, rl.BanDuration)
	}

	type anomalyDynamic struct {
		Enabled    bool                   `json:"enabled"`
		MinPackets int                    `json:"min_packets"`
		Ports      []int                  `json:"ports"`
		Baseline   anomaly.BaselineConfig `json:"baseline"`
		Attacks    anomaly.AttacksConfig  `json:"attacks"`
	}
	var ad anomalyDynamic
	if ok, err := svc.LoadTo("anomaly_detection", &ad); err != nil {
		logger.Warnf("[Main] Failed to load anomaly_detection dynamic config from DB: %v", err)
	} else if ok {
		cfg.AnomalyDetection.Enabled = ad.Enabled
		if ad.MinPackets > 0 { cfg.AnomalyDetection.MinPackets = ad.MinPackets }
		if len(ad.Ports) > 0 { cfg.AnomalyDetection.Ports = ad.Ports }
		if ad.Baseline.MinSampleCount > 0 {
			cfg.AnomalyDetection.Baseline = config.BaselineConfig{
				MinSampleCount: ad.Baseline.MinSampleCount,
				SigmaMultiplier: ad.Baseline.SigmaMultiplier,
				MinThreshold:    ad.Baseline.MinThreshold,
				MaxAge:          ad.Baseline.MaxAge,
				BlockDuration:   ad.Baseline.BlockDuration,
			}
		}
		if ad.Attacks.SynFlood.RatioThreshold > 0 {
			cfg.AnomalyDetection.Attacks = config.AttacksConfig{
				SynFlood: config.AttackConfig{
					Enabled: ad.Attacks.SynFlood.Enabled, RatioThreshold: ad.Attacks.SynFlood.RatioThreshold,
					BlockDuration: ad.Attacks.SynFlood.BlockDuration, MinPackets: ad.Attacks.SynFlood.MinPackets,
				},
				UdpFlood: config.AttackConfig{
					Enabled: ad.Attacks.UdpFlood.Enabled, RatioThreshold: ad.Attacks.UdpFlood.RatioThreshold,
					BlockDuration: ad.Attacks.UdpFlood.BlockDuration, MinPackets: ad.Attacks.UdpFlood.MinPackets,
				},
				IcmpFlood: config.AttackConfig{
					Enabled: ad.Attacks.IcmpFlood.Enabled, RatioThreshold: ad.Attacks.IcmpFlood.RatioThreshold,
					BlockDuration: ad.Attacks.IcmpFlood.BlockDuration, MinPackets: ad.Attacks.IcmpFlood.MinPackets,
				},
				AckFlood: config.AttackConfig{
					Enabled: ad.Attacks.AckFlood.Enabled, RatioThreshold: ad.Attacks.AckFlood.RatioThreshold,
					BlockDuration: ad.Attacks.AckFlood.BlockDuration, MinPackets: ad.Attacks.AckFlood.MinPackets,
				},
			}
		}
		portsStr := fmt.Sprintf("%v", ad.Ports)
		loaded["anomaly_detection"] = fmt.Sprintf("enabled=%v, min_packets=%d, ports=%s",
			ad.Enabled, ad.MinPackets, portsStr)
	}

	type geoDynamic struct {
		Enabled          bool     `json:"enabled"`
		Mode             string   `json:"mode"`
		AllowedCountries []string `json:"allowed_countries"`
	}
	var geo geoDynamic
	if ok, err := svc.LoadTo("geo_blocking", &geo); err != nil {
		logger.Warnf("[Main] Failed to load geo_blocking dynamic config from DB: %v", err)
	} else if ok {
		cfg.GeoBlocking.Enabled = geo.Enabled
		if geo.Mode != "" { cfg.GeoBlocking.Mode = geo.Mode }
		if geo.AllowedCountries != nil { cfg.GeoBlocking.AllowedCountries = geo.AllowedCountries }
		loaded["geo_blocking"] = fmt.Sprintf("enabled=%v, mode=%s, countries=%v",
			geo.Enabled, geo.Mode, geo.AllowedCountries)
	}

	type intelDynamic struct {
		Enabled bool `json:"enabled"`
	}
	var intel intelDynamic
	if ok, err := svc.LoadTo("intel", &intel); err != nil {
		logger.Warnf("[Main] Failed to load intel dynamic config from DB: %v", err)
	} else if ok {
		cfg.Intel.Enabled = intel.Enabled
		loaded["intel"] = fmt.Sprintf("enabled=%v", intel.Enabled)
	}

	modules := []string{"failguard", "waf", "rate_limit", "anomaly_detection", "geo_blocking", "intel"}
	logger.Info("[Main] Dynamic config loaded (DB values override YAML):")
	for _, mod := range modules {
		if val, exists := loaded[mod]; exists {
			logger.Infof("[Main] [DynamicConfig] %-20s → DB override       %s", mod, val)
		} else {
			logger.Infof("[Main] [DynamicConfig] %-20s → YAML default      (no DB record)", mod)
		}
	}
}
