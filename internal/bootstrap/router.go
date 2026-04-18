package bootstrap

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/database"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/handles"
	"rho-aias/internal/routers"
	"rho-aias/internal/services"
	"rho-aias/internal/threatintel"

	"github.com/gin-gonic/gin"
)

// RegisterAllRoutes 统一注册所有路由
func RegisterAllRoutes(
	api *gin.RouterGroup,
	core *CoreDependencies,
	dbDeps *Databases,
	detectorDeps *DetectorDeps,
	anomalyDeps *AnomalyDeps,
	authDeps *AuthDeps,
) {
	enforcer := authDeps.Enforcer
	authSvc := authDeps.AuthService
	apiKeySvc := authDeps.APIKeyService

	routers.RegisterAuthRoutes(api, authDeps.AuthHandle, authDeps.AuthService, authDeps.APIKeyService, enforcer)

	routers.RegisterAPIKeyRoutes(api, authDeps.APIKeyHandle, enforcer, authSvc, apiKeySvc)
	routers.RegisterUserRoutes(api, authDeps.UserHandle, enforcer, authSvc, apiKeySvc)
	routers.RegisterAuditRoutes(api, authDeps.AuditHandle, enforcer, authSvc, apiKeySvc)

	routers.RegisterManualRoutes(api, core.blacklistHandle, enforcer, authSvc, apiKeySvc)
	routers.RegisterWhitelistRoutes(api, core.WhitelistHandle, enforcer, authSvc, apiKeySvc)
	routers.RegisterBlockLogRoutes(api, core.BlockLogHandle, enforcer, authSvc, apiKeySvc)

	ruleQueryHandle := handles.NewRuleQueryHandle(core.XDP)
	routers.RegisterRuleRoutes(api, ruleQueryHandle, enforcer, authSvc, apiKeySvc)

	registerBizRoutes(api, core.XDP, dbDeps.BizDB, detectorDeps.IntelMgr, detectorDeps.GeoMgr,
		enforcer, authSvc, apiKeySvc)

	// ConfigHandle
	configHandle := newConfigHandle(dbDeps.DynamicConfigSvc, detectorDeps, anomalyDeps, core.XDP)
	routers.RegisterConfigRoutes(api, configHandle, enforcer, authSvc, apiKeySvc)
}

// registerBizRoutes 注册需要 bizDB 的业务路由
func registerBizRoutes(
	api *gin.RouterGroup,
	xdp *ebpfs.Xdp,
	bizDB *database.Database,
	intelMgr *threatintel.Manager,
	geoMgr *geoblocking.Manager,
	enforcer *casbin.Enforcer,
	authSvc *services.AuthService,
	apiKeySvc *services.APIKeyService,
) {
	if intelMgr != nil {
		intelHandle := handles.NewIntelHandle(intelMgr)
		routers.RegisterIntelRoutes(api, intelHandle, enforcer, authSvc, apiKeySvc)
	}

	if geoMgr != nil {
		geoHandle := handles.NewGeoBlockingHandle(geoMgr)
		routers.RegisterGeoBlockingRoutes(api, geoHandle, enforcer, authSvc, apiKeySvc)
	}

	banRecordService := services.NewBanRecordService(bizDB.DB)
	banRecordHandle := handles.NewBanRecordHandle(banRecordService, xdp)
	routers.RegisterBanRecordRoutes(api, banRecordHandle, enforcer, authSvc, apiKeySvc)
}

// newConfigHandle 创建 ConfigHandle（包内使用）
func newConfigHandle(
	dynamicConfigSvc *services.DynamicConfigService,
	detectors *DetectorDeps,
	anomaly *AnomalyDeps,
	xdp *ebpfs.Xdp,
) *handles.ConfigHandle {
	configHandle := handles.NewConfigHandle(
		dynamicConfigSvc,
		detectors.FailGuardMonitor,
		detectors.WAFMonitor,
		detectors.RateLimitMonitor,
		anomaly.Detector,
		detectors.GeoMgr,
		detectors.IntelMgr,
		xdp,
	)
	configHandle.SetAnomalyController(xdp, anomaly.RecordPacketFn)
	return configHandle
}
