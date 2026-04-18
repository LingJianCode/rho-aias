package bootstrap

import (
	"rho-aias/internal/anomaly"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/internal/models"
	"rho-aias/internal/services"

	"gorm.io/gorm"
)

// AnomalyDeps 异常检测初始化结果
type AnomalyDeps struct {
	Manager        *anomaly.Manager
	RecordPacketFn ebpfs.AnomalyEventCallback
}

// InitAnomaly 初始化异常检测模块（含 eBPF 事件监听）
func InitAnomaly(
	cfg *config.Config,
	xdp *ebpfs.Xdp,
	bizDB *gorm.DB,
	whitelistChecker *manual.WhitelistChecker,
) *AnomalyDeps {

	anomalyConfig := anomaly.AnomalyDetectionConfig{
		Enabled:         cfg.AnomalyDetection.Enabled,
		SampleRate:      cfg.AnomalyDetection.SampleRate,
		CheckInterval:   cfg.AnomalyDetection.CheckInterval,
		MinPackets:      cfg.AnomalyDetection.MinPackets,
		CleanupInterval: cfg.AnomalyDetection.CleanupInterval,
		Ports:           cfg.AnomalyDetection.Ports,
		Baseline: anomaly.BaselineConfig{
			MinSampleCount:  cfg.AnomalyDetection.Baseline.MinSampleCount,
			SigmaMultiplier: cfg.AnomalyDetection.Baseline.SigmaMultiplier,
			MinThreshold:    cfg.AnomalyDetection.Baseline.MinThreshold,
			MaxAge:          cfg.AnomalyDetection.Baseline.MaxAge,
			BlockDuration:   cfg.AnomalyDetection.Baseline.BlockDuration,
		},
		Attacks: anomaly.AttacksConfig{
			SynFlood: anomaly.AttackConfig{
				Enabled:        cfg.AnomalyDetection.Attacks.SynFlood.Enabled,
				RatioThreshold: cfg.AnomalyDetection.Attacks.SynFlood.RatioThreshold,
				BlockDuration:  cfg.AnomalyDetection.Attacks.SynFlood.BlockDuration,
				MinPackets:     cfg.AnomalyDetection.Attacks.SynFlood.MinPackets,
			},
			UdpFlood: anomaly.AttackConfig{
				Enabled:        cfg.AnomalyDetection.Attacks.UdpFlood.Enabled,
				RatioThreshold: cfg.AnomalyDetection.Attacks.UdpFlood.RatioThreshold,
				BlockDuration:  cfg.AnomalyDetection.Attacks.UdpFlood.BlockDuration,
				MinPackets:     cfg.AnomalyDetection.Attacks.UdpFlood.MinPackets,
			},
			IcmpFlood: anomaly.AttackConfig{
				Enabled:        cfg.AnomalyDetection.Attacks.IcmpFlood.Enabled,
				RatioThreshold: cfg.AnomalyDetection.Attacks.IcmpFlood.RatioThreshold,
				BlockDuration:  cfg.AnomalyDetection.Attacks.IcmpFlood.BlockDuration,
				MinPackets:     cfg.AnomalyDetection.Attacks.IcmpFlood.MinPackets,
			},
			AckFlood: anomaly.AttackConfig{
				Enabled:        cfg.AnomalyDetection.Attacks.AckFlood.Enabled,
				RatioThreshold: cfg.AnomalyDetection.Attacks.AckFlood.RatioThreshold,
				BlockDuration:  cfg.AnomalyDetection.Attacks.AckFlood.BlockDuration,
				MinPackets:     cfg.AnomalyDetection.Attacks.AckFlood.MinPackets,
			},
		},
	}

	blockCallback := func(ip string, duration int, reason string) error {
		if whitelistChecker.IsWhitelisted(ip) {
			logger.Infof("[AnomalyDetection] IP %s is whitelisted, skipping block", ip)
			return nil
		}
		err := xdp.AddRuleWithSourceAndExpiry(ip, ebpfs.SourceMaskAnomaly, duration)
		if err != nil {
			logger.Errorf("[AnomalyDetection] Failed to block IP %s: %v", ip, err)
			return err
		}
		banRecordService := services.NewBanRecordService(bizDB)
		if err := banRecordService.UpsertActiveBan(ip, models.BanSourceAnomaly, reason, duration); err != nil {
			logger.Warnf("[AnomalyDetection] Failed to persist ban record for IP %s: %v", ip, err)
		}
		logger.Infof("[AnomalyDetection] Blocked IP %s for %ds, reason: %s", ip, duration, reason)
		return nil
	}

	unblockCallback := func(ip string) error {
		_, _, _, err := xdp.UpdateRuleSourceMask(ip, ebpfs.SourceMaskAnomaly)
		if err != nil {
			logger.Warnf("[AnomalyDetection] Failed to unblock IP %s: %v", ip, err)
			return err
		}
		banRecordService := services.NewBanRecordService(bizDB)
		if err := banRecordService.MarkExpired(ip, models.BanSourceAnomaly); err != nil {
			logger.Warnf("[AnomalyDetection] Failed to mark ban record expired for IP %s: %v", ip, err)
		}
		logger.Infof("[AnomalyDetection] Unblocked IP %s (ban expired)", ip)
		return nil
	}

	var manager *anomaly.Manager

	recordPacketFn := func(srcIP string, protocol uint8, tcpFlags uint8, pktSize uint32) {
		manager.RecordPacket(srcIP, protocol, tcpFlags, pktSize)
	}

	manager = anomaly.NewManager(anomalyConfig, blockCallback, unblockCallback)

	if cfg.AnomalyDetection.Enabled {
		if err := manager.Start(); err != nil {
			logger.Warnf("[Main] Anomaly manager start failed: %v", err)
		} else {
			logger.Info("[Main] Anomaly detection module initialized")

			if err := xdp.SetAnomalyConfig(true, uint32(cfg.AnomalyDetection.SampleRate)); err != nil {
				logger.Warnf("[Main] Failed to set anomaly config: %v", err)
			}

			ports := make([]uint32, len(cfg.AnomalyDetection.Ports))
			for i, p := range cfg.AnomalyDetection.Ports {
				ports[i] = uint32(p)
			}
			portFilterEnabled := len(ports) > 0
			if err := xdp.SetAnomalyPortFilter(portFilterEnabled, ports); err != nil {
				logger.Warnf("[Main] Failed to set anomaly port filter: %v", err)
			}

			go xdp.MonitorAnomalyEvents(recordPacketFn, nil)
		}
	}

	return &AnomalyDeps{
		Manager:        manager,
		RecordPacketFn: recordPacketFn,
	}
}
