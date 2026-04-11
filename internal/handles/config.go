package handles

import (
	"encoding/json"
	"fmt"

	"rho-aias/internal/anomaly"
	"rho-aias/internal/failguard"
	"rho-aias/internal/logger"
	"rho-aias/internal/ratelimit"
	"rho-aias/internal/response"
	"rho-aias/internal/services"
	"rho-aias/internal/waf"

	"github.com/gin-gonic/gin"
)

// 支持动态配置的模块名常量
const (
	ModuleFailGuard        = "failguard"
	ModuleWAF              = "waf"
	ModuleRateLimit        = "rate_limit"
	ModuleAnomalyDetection = "anomaly_detection"
	ModuleGeoBlocking      = "geo_blocking"
	ModuleIntel            = "intel"
)

// ConfigHandle 统一配置 API 处理器
type ConfigHandle struct {
	configService *services.DynamicConfigService

	// 各模块实例（可选，nil 表示未初始化）
	failguardMonitor *failguard.Monitor
	wafMonitor       *waf.Monitor
	rateLimitMonitor *ratelimit.Monitor
	anomalyDetector  *anomaly.Detector
	geoBlockingMgr   GeoBlockingConfigUpdater
	intelMgr         IntelConfigUpdater
}

// GeoBlockingConfigUpdater GeoBlocking 配置更新接口
type GeoBlockingConfigUpdater interface {
	UpdateConfig(enabled bool, mode string, countries []string) error
	GetConfig() map[string]interface{}
}

// IntelConfigUpdater 情报模块配置更新接口
type IntelConfigUpdater interface {
	UpdateConfig(enabled bool)
	UpdateSourceConfig(sourceID string, enabled bool, schedule string, url string) error
	GetConfig() map[string]interface{}
}

// NewConfigHandle 创建统一配置处理器
func NewConfigHandle(
	configService *services.DynamicConfigService,
	failguardMonitor *failguard.Monitor,
	wafMonitor *waf.Monitor,
	rateLimitMonitor *ratelimit.Monitor,
	anomalyDetector *anomaly.Detector,
	geoBlockingMgr GeoBlockingConfigUpdater,
	intelMgr IntelConfigUpdater,
) *ConfigHandle {
	return &ConfigHandle{
		configService:    configService,
		failguardMonitor: failguardMonitor,
		wafMonitor:       wafMonitor,
		rateLimitMonitor: rateLimitMonitor,
		anomalyDetector:  anomalyDetector,
		geoBlockingMgr:   geoBlockingMgr,
		intelMgr:         intelMgr,
	}
}

// GetAllConfig 获取所有模块的动态配置概览
func (h *ConfigHandle) GetAllConfig(c *gin.Context) {
	result := make(map[string]interface{})

	// 从 DB 加载持久化的配置
	records, err := h.configService.GetAll()
	if err != nil {
		response.InternalError(c, "Failed to load config from DB: "+err.Error())
		return
	}

	// 将 DB 记录转为 map
	dbConfigs := make(map[string]json.RawMessage)
	for _, r := range records {
		dbConfigs[r.Module] = json.RawMessage(r.Value)
	}

	// 构建每个模块的配置，优先使用运行时值
	modules := []string{ModuleFailGuard, ModuleWAF, ModuleRateLimit, ModuleAnomalyDetection, ModuleGeoBlocking, ModuleIntel}
	for _, module := range modules {
		runtimeConfig := h.getRuntimeConfig(module)
		if runtimeConfig != nil {
			result[module] = runtimeConfig
		} else if raw, ok := dbConfigs[module]; ok {
			// 模块未运行但有持久化配置
			result[module] = json.RawMessage(raw)
		}
	}

	response.OK(c, result)
}

// GetModuleConfig 获取指定模块的动态配置
func (h *ConfigHandle) GetModuleConfig(c *gin.Context) {
	module := c.Param("module")
	if !isValidModule(module) {
		response.BadRequest(c, "Invalid module name, supported: failguard, waf, rate_limit, anomaly_detection, geo_blocking, intel")
		return
	}

	runtimeConfig := h.getRuntimeConfig(module)
	if runtimeConfig != nil {
		response.OK(c, runtimeConfig)
		return
	}

	// 运行时无值，从 DB 加载
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

// UpdateModuleConfig 更新指定模块的动态配置
func (h *ConfigHandle) UpdateModuleConfig(c *gin.Context) {
	module := c.Param("module")
	if !isValidModule(module) {
		response.BadRequest(c, "Invalid module name, supported: failguard, waf, rate_limit, anomaly_detection, geo_blocking, intel")
		return
	}

	var raw json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// 1. 调用模块 UpdateConfig（内存即时生效）
	if err := h.applyConfig(module, raw); err != nil {
		response.InternalError(c, "Failed to apply config: "+err.Error())
		return
	}

	// 2. 持久化到 DB
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		response.InternalError(c, "Failed to parse config for persistence: "+err.Error())
		return
	}
	if err := h.configService.Set(module, value); err != nil {
		response.InternalError(c, "Failed to persist config: "+err.Error())
		return
	}

	logger.Infof("[ConfigAPI] Module %s config updated and persisted", module)
	response.OKMsg(c, fmt.Sprintf("Module %s config updated successfully", module))
}

// getRuntimeConfig 获取模块运行时配置
func (h *ConfigHandle) getRuntimeConfig(module string) interface{} {
	switch module {
	case ModuleFailGuard:
		if h.failguardMonitor != nil {
			return h.failguardMonitor.GetConfig()
		}
	case ModuleWAF:
		if h.wafMonitor != nil {
			return h.wafMonitor.GetConfig()
		}
	case ModuleRateLimit:
		if h.rateLimitMonitor != nil {
			return h.rateLimitMonitor.GetConfig()
		}
	case ModuleAnomalyDetection:
		if h.anomalyDetector != nil {
			return h.anomalyDetector.GetConfig()
		}
	case ModuleGeoBlocking:
		if h.geoBlockingMgr != nil {
			return h.geoBlockingMgr.GetConfig()
		}
	case ModuleIntel:
		if h.intelMgr != nil {
			return h.intelMgr.GetConfig()
		}
	}
	return nil
}

// applyConfig 将配置应用到模块
func (h *ConfigHandle) applyConfig(module string, raw json.RawMessage) error {
	switch module {
	case ModuleFailGuard:
		return h.applyFailGuardConfig(raw)
	case ModuleWAF:
		return h.applyWAFConfig(raw)
	case ModuleRateLimit:
		return h.applyRateLimitConfig(raw)
	case ModuleAnomalyDetection:
		return h.applyAnomalyDetectionConfig(raw)
	case ModuleGeoBlocking:
		return h.applyGeoBlockingConfig(raw)
	case ModuleIntel:
		return h.applyIntelConfig(raw)
	default:
		return fmt.Errorf("unsupported module: %s", module)
	}
}

// FailGuard 动态配置请求
type failGuardConfigRequest struct {
	Enabled     *bool  `json:"enabled"`
	MaxRetry    *int   `json:"max_retry"`
	FindTime    *int   `json:"find_time"`
	BanDuration *int   `json:"ban_duration"`
	Mode        string `json:"mode"`
}

func (h *ConfigHandle) applyFailGuardConfig(raw json.RawMessage) error {
	if h.failguardMonitor == nil {
		return fmt.Errorf("failguard module is not initialized")
	}

	var req failGuardConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	// 获取当前配置作为默认值
	current := h.failguardMonitor.GetConfig()

	enabled := boolValue(current["enabled"].(bool), req.Enabled)
	maxRetry := intValue(current["max_retry"].(int), req.MaxRetry)
	findTime := intValue(current["find_time"].(int), req.FindTime)
	banDuration := intValue(current["ban_duration"].(int), req.BanDuration)
	mode := req.Mode
	if mode == "" {
		mode = current["mode"].(string)
	}

	h.failguardMonitor.UpdateConfig(enabled, maxRetry, findTime, banDuration, mode)
	return nil
}

// WAF 动态配置请求
type wafConfigRequest struct {
	Enabled     *bool `json:"enabled"`
	BanDuration *int  `json:"ban_duration"`
}

func (h *ConfigHandle) applyWAFConfig(raw json.RawMessage) error {
	if h.wafMonitor == nil {
		return fmt.Errorf("waf module is not initialized")
	}

	var req wafConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	current := h.wafMonitor.GetConfig()
	enabled := boolValue(current["enabled"].(bool), req.Enabled)
	banDuration := intValue(current["ban_duration"].(int), req.BanDuration)

	h.wafMonitor.UpdateConfig(enabled, banDuration)
	return nil
}

// RateLimit 动态配置请求
type rateLimitConfigRequest struct {
	Enabled     *bool `json:"enabled"`
	BanDuration *int  `json:"ban_duration"`
}

func (h *ConfigHandle) applyRateLimitConfig(raw json.RawMessage) error {
	if h.rateLimitMonitor == nil {
		return fmt.Errorf("rate_limit module is not initialized")
	}

	var req rateLimitConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	current := h.rateLimitMonitor.GetConfig()
	enabled := boolValue(current["enabled"].(bool), req.Enabled)
	banDuration := intValue(current["ban_duration"].(int), req.BanDuration)

	h.rateLimitMonitor.UpdateConfig(enabled, banDuration)
	return nil
}

// AnomalyDetection 动态配置请求
func (h *ConfigHandle) applyAnomalyDetectionConfig(raw json.RawMessage) error {
	if h.anomalyDetector == nil {
		return fmt.Errorf("anomaly_detection module is not initialized")
	}

	var cfg anomaly.AnomalyDetectionConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	h.anomalyDetector.UpdateConfig(cfg)
	return nil
}

// GeoBlocking 动态配置请求
type geoBlockingConfigRequest struct {
	Enabled          *bool    `json:"enabled"`
	Mode             string   `json:"mode"`
	AllowedCountries []string `json:"allowed_countries"`
}

func (h *ConfigHandle) applyGeoBlockingConfig(raw json.RawMessage) error {
	if h.geoBlockingMgr == nil {
		return fmt.Errorf("geo_blocking module is not initialized")
	}

	var req geoBlockingConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	current := h.geoBlockingMgr.GetConfig()
	enabled := boolValue(current["enabled"].(bool), req.Enabled)
	mode := req.Mode
	if mode == "" {
		mode = current["mode"].(string)
	}
	countries := req.AllowedCountries
	if countries == nil {
		countriesIface, _ := current["allowed_countries"].([]string)
		if countriesIface != nil {
			countries = countriesIface
		}
	}

	return h.geoBlockingMgr.UpdateConfig(enabled, mode, countries)
}

// Intel 动态配置请求
type intelConfigRequest struct {
	Enabled *bool                       `json:"enabled"`
	Sources map[string]intelSourceConfig `json:"sources"`
}

type intelSourceConfig struct {
	Enabled  *bool  `json:"enabled"`
	Schedule string `json:"schedule"`
	URL      string `json:"url"`
}

func (h *ConfigHandle) applyIntelConfig(raw json.RawMessage) error {
	if h.intelMgr == nil {
		return fmt.Errorf("intel module is not initialized")
	}

	var req intelConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	// 更新总开关
	if req.Enabled != nil {
		h.intelMgr.UpdateConfig(*req.Enabled)
	}

	// 更新各情报源配置
	for sourceID, srcCfg := range req.Sources {
		enabled := true
		if srcCfg.Enabled != nil {
			enabled = *srcCfg.Enabled
		}
		if err := h.intelMgr.UpdateSourceConfig(sourceID, enabled, srcCfg.Schedule, srcCfg.URL); err != nil {
			logger.Warnf("[ConfigAPI] Failed to update intel source %s: %v", sourceID, err)
		}
	}

	return nil
}

// isValidModule 检查模块名是否合法
func isValidModule(module string) bool {
	switch module {
	case ModuleFailGuard, ModuleWAF, ModuleRateLimit, ModuleAnomalyDetection, ModuleGeoBlocking, ModuleIntel:
		return true
	default:
		return false
	}
}

// boolValue 如果 ptr 不为 nil 则返回 *ptr，否则返回 def
func boolValue(def bool, ptr *bool) bool {
	if ptr != nil {
		return *ptr
	}
	return def
}

// intValue 如果 ptr 不为 nil 则返回 *ptr，否则返回 def
func intValue(def int, ptr *int) int {
	if ptr != nil {
		return *ptr
	}
	return def
}
