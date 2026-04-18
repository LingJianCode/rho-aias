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
	IntelMgr        *threatintel.Manager
	GeoMgr          *geoblocking.Manager
	WAFMgr          *waf.Manager
	RateLimitMgr    *ratelimit.Manager
	FailGuardMgr    *failguard.Manager
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

	wafMgr := waf.NewManager(&cfg.WAF, xdp, ctx,
		watcher.NewOffsetStore(cfg.WAF.OffsetStateFile),
		services.NewBanRecordService(dbConn),
		whitelistChecker.IsWhitelisted,
	)
	if cfg.WAF.Enabled {
		if err := wafMgr.Start(); err != nil {
			logger.Warnf("[Main] WAF manager start failed: %v", err)
		} else {
			logger.Info("[Main] WAF module initialized")
		}
	}

	rateLimitMgr := ratelimit.NewManager(&cfg.RateLimit, xdp, ctx,
		watcher.NewOffsetStore(cfg.RateLimit.OffsetStateFile),
		services.NewBanRecordService(dbConn),
		whitelistChecker.IsWhitelisted,
	)
	if cfg.RateLimit.Enabled {
		if err := rateLimitMgr.Start(); err != nil {
			logger.Warnf("[Main] Rate Limit manager start failed: %v", err)
		} else {
			logger.Info("[Main] Rate Limit module initialized")
		}
	}

	failguardMgr := failguard.NewManager(&cfg.FailGuard, xdp, ctx,
		watcher.NewOffsetStore(cfg.FailGuard.OffsetStateFile),
		services.NewBanRecordService(dbConn),
		whitelistChecker.IsWhitelisted,
	)
	if cfg.FailGuard.Enabled {
		if err := failguardMgr.Start(); err != nil {
			logger.Warnf("[Main] FailGuard manager start failed: %v", err)
		} else {
			logger.Info("[Main] FailGuard module initialized")
		}
	}

	return &DetectorDeps{
		IntelMgr:     intelMgr,
		GeoMgr:       geoMgr,
		WAFMgr:       wafMgr,
		RateLimitMgr: rateLimitMgr,
		FailGuardMgr: failguardMgr,
	}
}
