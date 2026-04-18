package bootstrap

import (
	"context"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/failguard"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/internal/ratelimit"
	"rho-aias/internal/services"
	"rho-aias/internal/threatintel"
	"rho-aias/internal/waf"
	"rho-aias/internal/watcher"

	"gorm.io/gorm"
)

// DetectorDeps 检测模块工厂结果
type DetectorDeps struct {
	IntelMgr         *threatintel.Manager
	GeoMgr           *geoblocking.Manager
	WAFMonitor       *waf.Monitor
	RateLimitMonitor *ratelimit.Monitor
	FailGuardMonitor *failguard.Monitor
}

// InitDetectors 初始化 Intel / Geo / WAF / RateLimit / FailGuard
func InitDetectors(
	cfg *config.Config,
	xdp *ebpfs.Xdp,
	ctx context.Context,
	dbConn *gorm.DB,
	whitelistChecker *manual.WhitelistChecker,
) *DetectorDeps {

	intelMgr := threatintel.NewManager(&cfg.Intel, xdp, dbConn)
	if cfg.Intel.Enabled {
		if err := intelMgr.Start(); err != nil {
			logger.Warnf("[Main] Intel manager start failed: %v", err)
		} else {
			logger.Info("[Main] Intelligence module initialized")
		}
	}

	geoMgr := geoblocking.NewManager(&cfg.GeoBlocking, xdp, dbConn)
	if cfg.GeoBlocking.Enabled {
		if err := geoMgr.Start(); err != nil {
			logger.Warnf("[Main] Geo-blocking manager start failed: %v", err)
		} else {
			logger.Info("[Main] Geo-blocking module initialized")
		}
	}

	wafMonitor := waf.NewMonitor(&cfg.WAF, xdp, ctx)
	wafMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.WAF.OffsetStateFile))
	wafMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
	wafMonitor.SetBanRecordStore(services.NewBanRecordService(dbConn))
	if cfg.WAF.Enabled {
		if err := wafMonitor.Start(); err != nil {
			logger.Warnf("[Main] WAF monitor start failed: %v", err)
		} else {
			logger.Info("[Main] WAF monitor module initialized")
		}
	}

	rateLimitMonitor := ratelimit.NewMonitor(&cfg.RateLimit, xdp, ctx)
	rateLimitMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.RateLimit.OffsetStateFile))
	rateLimitMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
	rateLimitMonitor.SetBanRecordStore(services.NewBanRecordService(dbConn))
	if cfg.RateLimit.Enabled {
		if err := rateLimitMonitor.Start(); err != nil {
			logger.Warnf("[Main] Rate Limit monitor start failed: %v", err)
		} else {
			logger.Info("[Main] Rate Limit monitor module initialized")
		}
	}

	failguardMonitor := failguard.NewMonitor(&cfg.FailGuard, xdp, ctx)
	failguardMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.FailGuard.OffsetStateFile))
	failguardMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
	failguardMonitor.SetBanRecordStore(services.NewBanRecordService(dbConn))
	if cfg.FailGuard.Enabled {
		if err := failguardMonitor.Start(); err != nil {
			logger.Warnf("[Main] FailGuard monitor start failed: %v", err)
		} else {
			logger.Info("[Main] FailGuard module initialized")
		}
	}

	return &DetectorDeps{
		IntelMgr:         intelMgr,
		GeoMgr:           geoMgr,
		WAFMonitor:       wafMonitor,
		RateLimitMonitor: rateLimitMonitor,
		FailGuardMonitor: failguardMonitor,
	}
}
