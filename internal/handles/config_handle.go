package handles

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/failguard"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"
	"rho-aias/internal/ratelimit"
	"rho-aias/internal/response"
	"rho-aias/internal/services"
	"rho-aias/internal/threatintel"
	"rho-aias/internal/waf"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// supportedModules 错误提示用合法模块名列表
var supportedModules = []string{
	models.ModuleFailGuard, models.ModuleWAF, models.ModuleRateLimit,
	models.ModuleAnomalyDetection, models.ModuleGeoBlocking, models.ModuleIntel,
	models.ModuleBlocklogEvents, models.ModuleEgressLimit,
}

// IsValidModule 导出给外部调用
var IsValidModule = models.IsValidModule

// ConfigHandle 统一配置 API 处理器
type ConfigHandle struct {
	configService         *services.DynamicConfigService
	validate              *validator.Validate
	failguardMgr    *failguard.Manager
	wafMgr          *waf.Manager
	rateLimitMgr    *ratelimit.Manager
	anomalyDetector       *anomaly.Manager
	geoBlockingMgr        *geoblocking.Manager
	intelMgr              *threatintel.Manager
	xdp                   *ebpfs.Xdp
	tcEgress              *ebpfs.TcEgress
	anomalyController     *ebpfs.Xdp
	anomalyRecordPacketFn ebpfs.AnomalyEventCallback
	anomalyMonitorCancel  context.CancelFunc
	mu                    sync.Mutex
}

func NewConfigHandle(
	configService *services.DynamicConfigService,
	failguardMgr *failguard.Manager,
	wafMgr *waf.Manager,
	rateLimitMgr *ratelimit.Manager,
	anomalyDetector *anomaly.Manager,
	geoBlockingMgr *geoblocking.Manager,
	intelMgr *threatintel.Manager,
	xdp *ebpfs.Xdp,
	tcEgress *ebpfs.TcEgress,
	anomalyController *ebpfs.Xdp,
	anomalyRecordPacketFn ebpfs.AnomalyEventCallback,
) *ConfigHandle {
	h := &ConfigHandle{
		configService, validator.New(),
		failguardMgr, wafMgr, rateLimitMgr,
		anomalyDetector, geoBlockingMgr, intelMgr, xdp,
		tcEgress, anomalyController, anomalyRecordPacketFn, nil, sync.Mutex{},
	}
	return h
}

// ========== HTTP API Handlers ==========

func (h *ConfigHandle) GetAllConfig(c *gin.Context) {
	result := make(map[string]interface{})

	records, err := h.configService.GetAll()
	if err != nil {
		response.InternalError(c, "Failed to load config from DB: "+err.Error())
		return
	}

	dbConfigs := make(map[string]json.RawMessage)
	for _, r := range records {
		dbConfigs[r.Module] = json.RawMessage(r.Value)
	}

	modules := []string{models.ModuleFailGuard, models.ModuleWAF, models.ModuleRateLimit, models.ModuleAnomalyDetection, models.ModuleGeoBlocking, models.ModuleIntel, models.ModuleBlocklogEvents, models.ModuleEgressLimit}
	for _, module := range modules {
		runtimeConfig := h.getRuntimeConfig(module)
		if runtimeConfig != nil {
			result[module] = runtimeConfig
		} else if raw, ok := dbConfigs[module]; ok {
			result[module] = json.RawMessage(raw)
		}
	}

	response.OK(c, result)
}

func (h *ConfigHandle) GetModuleConfig(c *gin.Context) {
	module := c.Param("module")
	if !IsValidModule(module) {
		response.BadRequest(c, fmt.Sprintf("Invalid module name, supported: %v", supportedModules))
		return
	}

	runtimeConfig := h.getRuntimeConfig(module)
	if runtimeConfig != nil {
		response.OK(c, runtimeConfig)
		return
	}

	record, err := h.configService.Get(module)
	if err != nil {
		response.InternalError(c, "Failed to load config: "+err.Error())
		return
	}
	if record == nil {
		response.NotFound(c, "No config found for module: "+module)
		return
	}

	var data interface{}
	if err := json.Unmarshal([]byte(record.Value), &data); err != nil {
		response.InternalError(c, "Failed to parse config: "+err.Error())
		return
	}

	response.OK(c, data)
}

func (h *ConfigHandle) UpdateModuleConfig(c *gin.Context) {
	module := c.Param("module")
	if !IsValidModule(module) {
		response.BadRequest(c, fmt.Sprintf("Invalid module name, supported: %v", supportedModules))
		return
	}

	var raw json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	beforeRaw, _ := json.Marshal(h.getRuntimeConfig(module))

	if err := h.validateConfig(module, raw); err != nil {
		response.BadRequest(c, "Invalid config: "+err.Error())
		return
	}

	if err := h.applyConfig(module, raw); err != nil {
		response.InternalError(c, "Failed to apply config: "+err.Error())
		return
	}

	value, err := h.getMergedConfig(module)
	if err != nil {
		response.InternalError(c, "Failed to get merged config for persistence: "+err.Error())
		return
	}
	if err := h.configService.Set(module, value); err != nil {
		response.InternalError(c, "Failed to persist config: "+err.Error())
		return
	}

	afterRaw, _ := json.Marshal(value)
	logger.Infof("[ConfigAPI] Module %s updated: before=%s after=%s (persisted)", module, string(beforeRaw), string(afterRaw))
	response.OKMsg(c, fmt.Sprintf("Module %s config updated successfully", module))
}

// getRuntimeConfig 获取模块运行时配置
func (h *ConfigHandle) getRuntimeConfig(module string) interface{} {
	switch module {
	case models.ModuleFailGuard:
		return h.failguardMgr.GetConfig()
	case models.ModuleWAF:
		return h.wafMgr.GetConfig()
	case models.ModuleRateLimit:
		return h.rateLimitMgr.GetConfig()
	case models.ModuleAnomalyDetection:
		return h.anomalyDetector.GetConfig()
	case models.ModuleGeoBlocking:
		if h.geoBlockingMgr != nil {
			return h.geoBlockingMgr.GetConfig()
		}
	case models.ModuleIntel:
		if h.intelMgr != nil {
			return h.intelMgr.GetConfig()
		}
	case models.ModuleBlocklogEvents:
		return h.getXDPEventsRuntimeConfig()
	case models.ModuleEgressLimit:
		return h.getEgressLimitRuntimeConfig()
	}
	return nil
}

// applyConfig 将配置应用到模块
func (h *ConfigHandle) applyConfig(module string, raw json.RawMessage) error {
	switch module {
	case models.ModuleFailGuard:
		return h.applyFailGuardConfig(raw)
	case models.ModuleWAF:
		return h.applyWAFConfig(raw)
	case models.ModuleRateLimit:
		return h.applyRateLimitConfig(raw)
	case models.ModuleAnomalyDetection:
		return h.applyAnomalyDetectionConfig(raw)
	case models.ModuleGeoBlocking:
		return h.applyGeoBlockingConfig(raw)
	case models.ModuleIntel:
		return h.applyIntelConfig(raw)
	case models.ModuleBlocklogEvents:
		return h.applyBlocklogEventsConfig(raw)
	case models.ModuleEgressLimit:
		return h.applyEgressLimitConfig(raw)
	default:
		return fmt.Errorf("unsupported module: %s", module)
	}
}

// validateConfig 校验请求参数（使用 config.Runtime 结构体）
func (h *ConfigHandle) validateConfig(module string, raw json.RawMessage) error {
	switch module {
	case models.ModuleFailGuard:
		var req config.FailGuardRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleWAF:
		var req config.WAFRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleRateLimit:
		var req config.RateLimitRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleAnomalyDetection:
		var req config.AnomalyDetectionRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
		return validateAnomalyRuntimeFields(&req.Baseline, &req.Attacks)
	case models.ModuleGeoBlocking:
		var req config.GeoBlockingRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
		for sourceID, srcCfg := range req.Sources {
			if srcCfg.Schedule != "" && !isValidCronExpr(srcCfg.Schedule) {
				return fmt.Errorf("geo source '%s': invalid cron schedule '%s'", sourceID, srcCfg.Schedule)
			}
		}
		return nil
	case models.ModuleIntel:
		var req config.IntelRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
		for sourceID, srcCfg := range req.Sources {
			if srcCfg.Schedule != "" && !isValidCronExpr(srcCfg.Schedule) {
				return fmt.Errorf("source '%s': invalid cron schedule '%s'", sourceID, srcCfg.Schedule)
			}
		}
		return nil
	case models.ModuleBlocklogEvents:
		var req config.BlocklogEventsRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleEgressLimit:
		var req config.EgressLimitRuntime
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	default:
		return fmt.Errorf("unsupported module: %s", module)
	}
}

// getMergedConfig 获取模块当前合并后的完整配置（用于持久化）
func (h *ConfigHandle) getMergedConfig(module string) (interface{}, error) {
	switch module {
	case models.ModuleFailGuard:
		return h.failguardMgr.GetConfig(), nil
	case models.ModuleWAF:
		return h.wafMgr.GetConfig(), nil
	case models.ModuleRateLimit:
		return h.rateLimitMgr.GetConfig(), nil
	case models.ModuleAnomalyDetection:
		return h.anomalyDetector.GetConfig(), nil
	case models.ModuleGeoBlocking:
		if h.geoBlockingMgr == nil {
			return nil, fmt.Errorf("geo_blocking module is not initialized")
		}
		return h.geoBlockingMgr.GetConfig(), nil
	case models.ModuleIntel:
		if h.intelMgr == nil {
			return nil, fmt.Errorf("intel module is not initialized")
		}
		return h.intelMgr.GetConfig(), nil
	case models.ModuleBlocklogEvents:
		if h.xdp == nil {
			return nil, fmt.Errorf("blocklog_events module is not initialized (XDP not available)")
		}
		return h.getXDPEventsRuntimeConfig(), nil
	case models.ModuleEgressLimit:
		return h.getEgressLimitRuntimeConfig(), nil
	default:
		return nil, fmt.Errorf("unsupported module: %s", module)
	}
}

// getEgressLimitRuntimeConfig 获取 egress_limit 运行时配置
func (h *ConfigHandle) getEgressLimitRuntimeConfig() map[string]interface{} {
	if h.tcEgress == nil {
		return nil
	}
	cfg, err := h.tcEgress.GetEgressLimitConfig()
	if err != nil {
		return map[string]interface{}{
			"enabled":              false,
			"rate_mbps":            100.0,
			"burst_bytes":          125000,
			"drop_log_enabled":     false,
			"drop_log_sample_rate": 100,
		}
	}
	rateMbps := float64(cfg.RateBytes) * 8 / 1000000

	// 获取丢包日志配置
	dropCfg, err := h.tcEgress.GetDropLogConfig()
	dropLogEnabled := false
	dropLogSampleRate := uint32(100)
	if err == nil {
		dropLogEnabled = dropCfg.Enabled == 1
		dropLogSampleRate = dropCfg.SampleRate
	}

	return map[string]interface{}{
		"enabled":              cfg.Enabled == 1,
		"rate_mbps":            rateMbps,
		"burst_bytes":          cfg.BurstBytes,
		"drop_log_enabled":     dropLogEnabled,
		"drop_log_sample_rate": dropLogSampleRate,
	}
}
