package handles

import (
	"encoding/json"
	"fmt"
	"sync"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/failguard"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"
	"rho-aias/internal/ratelimit"
	"rho-aias/internal/response"
	"rho-aias/internal/services"
	"rho-aias/internal/waf"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// supportedModules 错误提示用合法模块名列表
var supportedModules = []string{
	models.ModuleFailGuard, models.ModuleWAF, models.ModuleRateLimit,
	models.ModuleAnomalyDetection, models.ModuleGeoBlocking, models.ModuleIntel,
	models.ModuleXDPEvents,
}

// IsValidModule 导出给外部调用
var IsValidModule = models.IsValidModule

// AnomalyController eBPF 异常检测操作接口
type AnomalyController interface {
	SetAnomalyConfig(enabled bool, sampleRate uint32) error
	SetAnomalyPortFilter(enabled bool, ports []uint32) error
	MonitorAnomalyEvents(callback ebpfs.AnomalyEventCallback)
}

type LifecycleManager struct {
	mu       sync.Mutex
	stoppers []func()
}

func (lm *LifecycleManager) Register(fn func()) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.stoppers = append(lm.stoppers, fn)
}
func (lm *LifecycleManager) ShutdownAll() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for i := len(lm.stoppers) - 1; i >= 0; i-- {
		lm.stoppers[i]()
	}
}

type GeoBlockingConfigUpdater interface {
	UpdateConfig(enabled bool, mode string, countries []string) error
	GetConfig() map[string]interface{}
}
type IntelConfigUpdater interface {
	UpdateConfig(enabled bool)
	UpdateSourceConfig(sourceID string, enabled bool, schedule string, url string) error
	GetConfig() map[string]interface{}
}

// ConfigHandle 统一配置 API 处理器
type ConfigHandle struct {
	configService         *services.DynamicConfigService
	validate              *validator.Validate
	failguardMonitor      *failguard.Monitor
	wafMonitor            *waf.Monitor
	rateLimitMonitor      *ratelimit.Monitor
	anomalyDetector       *anomaly.Detector
	geoBlockingMgr        GeoBlockingConfigUpdater
	intelMgr              IntelConfigUpdater
	xdp                   *ebpfs.Xdp
	anomalyController     AnomalyController
	anomalyRecordPacketFn ebpfs.AnomalyEventCallback
	lifecycle             *LifecycleManager
	mu                    sync.Mutex
}

func NewConfigHandle(
	configService *services.DynamicConfigService,
	failguardMonitor *failguard.Monitor,
	wafMonitor *waf.Monitor,
	rateLimitMonitor *ratelimit.Monitor,
	anomalyDetector *anomaly.Detector,
	geoBlockingMgr GeoBlockingConfigUpdater,
	intelMgr IntelConfigUpdater,
	xdp *ebpfs.Xdp,
) *ConfigHandle {
	lifecycle := &LifecycleManager{}
	h := &ConfigHandle{
		configService, validator.New(),
		failguardMonitor, wafMonitor, rateLimitMonitor,
		anomalyDetector, geoBlockingMgr, intelMgr, xdp, nil, nil, lifecycle, sync.Mutex{},
	}
	if failguardMonitor != nil {
		lifecycle.Register(failguardMonitor.Stop)
	}
	if wafMonitor != nil {
		lifecycle.Register(wafMonitor.Stop)
	}
	if rateLimitMonitor != nil {
		lifecycle.Register(rateLimitMonitor.Stop)
	}
	if anomalyDetector != nil {
		lifecycle.Register(anomalyDetector.Stop)
	}
	return h
}

func (h *ConfigHandle) GetLifecycle() *LifecycleManager { return h.lifecycle }
func (h *ConfigHandle) SetAnomalyController(c AnomalyController, f ebpfs.AnomalyEventCallback) {
	h.anomalyController = c
	h.anomalyRecordPacketFn = f
}
func (h *ConfigHandle) SetXDP(x *ebpfs.Xdp) { h.xdp = x }

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

	modules := []string{models.ModuleFailGuard, models.ModuleWAF, models.ModuleRateLimit, models.ModuleAnomalyDetection, models.ModuleGeoBlocking, models.ModuleIntel, models.ModuleXDPEvents}
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

// ========== 生命周期 / 恢复 / 调度方法 ==========

// RestoreAll 从 DB 恢复所有已持久化的模块配置到运行时（启动时调用）
func (h *ConfigHandle) RestoreAll() {
	records, err := h.configService.GetAll()
	if err != nil {
		logger.Warnf("[Restore] Failed to load configs from DB: %v", err)
		return
	}
	if len(records) == 0 {
		return
	}
	supported := map[string]bool{
		models.ModuleFailGuard: true, models.ModuleWAF: true, models.ModuleRateLimit: true,
		models.ModuleAnomalyDetection: true, models.ModuleGeoBlocking: true,
		models.ModuleIntel: true, models.ModuleXDPEvents: true,
	}
	for _, record := range records {
		if !supported[record.Module] {
			continue
		}
		raw := json.RawMessage(record.Value)
		if err := h.applyConfig(record.Module, raw); err != nil {
			logger.Warnf("[Restore] Failed to restore module %s: %v", record.Module, err)
		} else {
			logger.Infof("[Restored] Module %s config restored from DB", record.Module)
		}
	}
}

// getRuntimeConfig 获取模块运行时配置（调度到各子文件）
func (h *ConfigHandle) getRuntimeConfig(module string) interface{} {
	switch module {
	case models.ModuleFailGuard:
		return h.failguardMonitor.GetConfig()
	case models.ModuleWAF:
		return h.wafMonitor.GetConfig()
	case models.ModuleRateLimit:
		return h.rateLimitMonitor.GetConfig()
	case models.ModuleAnomalyDetection:
		return h.anomalyDetector.GetConfig()
	case models.ModuleGeoBlocking:
		if h.geoBlockingMgr != nil && !isNilInterface(h.geoBlockingMgr) {
			return h.geoBlockingMgr.GetConfig()
		}
	case models.ModuleIntel:
		if h.intelMgr != nil && !isNilInterface(h.intelMgr) {
			return h.intelMgr.GetConfig()
		}
	case models.ModuleXDPEvents:
		return h.getXDPEventsRuntimeConfig()
	}
	return nil
}

// applyConfig 将配置应用到模块（调度到各子文件）
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
	case models.ModuleXDPEvents:
		return h.applyXDPEventsConfig(raw)
	default:
		return fmt.Errorf("unsupported module: %s", module)
	}
}

// validateConfig 校验请求参数
func (h *ConfigHandle) validateConfig(module string, raw json.RawMessage) error {
	switch module {
	case models.ModuleFailGuard:
		var req failGuardConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleWAF:
		var req wafConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleRateLimit:
		var req rateLimitConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleAnomalyDetection:
		var req anomalyDetectionConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
		return validateAnomalyNestedFields(req.Baseline, req.Attacks)
	case models.ModuleGeoBlocking:
		var req geoBlockingConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		return h.validate.Struct(req)
	case models.ModuleIntel:
		var req intelConfigRequest
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
	case models.ModuleXDPEvents:
		var req xdpEventsConfigRequest
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
		return h.failguardMonitor.GetConfig(), nil
	case models.ModuleWAF:
		return h.wafMonitor.GetConfig(), nil
	case models.ModuleRateLimit:
		return h.rateLimitMonitor.GetConfig(), nil
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
	case models.ModuleXDPEvents:
		if h.xdp == nil {
			return nil, fmt.Errorf("xdp_events module is not initialized (XDP not available)")
		}
		return h.getXDPEventsRuntimeConfig(), nil
	default:
		return nil, fmt.Errorf("unsupported module: %s", module)
	}
}
