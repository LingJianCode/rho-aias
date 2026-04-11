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
	"github.com/go-playground/validator/v10"
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
	validate      *validator.Validate

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
		validate:         validator.New(),
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
	if !IsValidModule(module) {
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
	if !IsValidModule(module) {
		response.BadRequest(c, "Invalid module name, supported: failguard, waf, rate_limit, anomaly_detection, geo_blocking, intel")
		return
	}

	var raw json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// 0. 记录更新前配置快照（用于日志 diff）
	beforeRaw, _ := json.Marshal(h.getRuntimeConfig(module))

	// 1. 校验请求参数
	if err := h.validateConfig(module, raw); err != nil {
		response.BadRequest(c, "Invalid config: "+err.Error())
		return
	}

	// 2. 调用模块 UpdateConfig（内存即时生效）
	if err := h.applyConfig(module, raw); err != nil {
		response.InternalError(c, "Failed to apply config: "+err.Error())
		return
	}

	// 2. 持久化合并后的完整配置到 DB（而非原始请求值，确保重启后配置完整恢复）
	value, err := h.getMergedConfig(module)
	if err != nil {
		response.InternalError(c, "Failed to get merged config for persistence: "+err.Error())
		return
	}
	if err := h.configService.Set(module, value); err != nil {
		response.InternalError(c, "Failed to persist config: "+err.Error())
		return
	}

	// 3. 日志记录变更前后对比
	afterRaw, _ := json.Marshal(value)
	logger.Infof("[ConfigAPI] Module %s updated: before=%s after=%s (persisted)", module, string(beforeRaw), string(afterRaw))
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

// validateConfig 校验请求参数（使用 validator 库做边界检查）
func (h *ConfigHandle) validateConfig(module string, raw json.RawMessage) error {
	switch module {
	case ModuleFailGuard:
		var req failGuardConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
	case ModuleWAF:
		var req wafConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
	case ModuleRateLimit:
		var req rateLimitConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
	case ModuleAnomalyDetection:
		var req anomalyDetectionConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
		// 嵌套结构体校验：baseline 和 attacks 的数值字段
		if err := validateAnomalyNestedFields(req.Baseline, req.Attacks); err != nil {
			return err
		}
	case ModuleGeoBlocking:
		var req geoBlockingConfigRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("invalid format: %w", err)
		}
		if err := h.validate.Struct(req); err != nil {
			return err
		}
	case ModuleIntel:
		// Intel 配置校验较宽松（schedule/url 格式各异），仅做基本非空校验即可
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
	default:
		return fmt.Errorf("unsupported module: %s", module)
	}
	return nil
}

// getMergedConfig 获取模块当前合并后的完整配置（用于持久化）
func (h *ConfigHandle) getMergedConfig(module string) (interface{}, error) {
	switch module {
	case ModuleFailGuard:
		if h.failguardMonitor == nil {
			return nil, fmt.Errorf("failguard module is not initialized")
		}
		return h.failguardMonitor.GetConfig(), nil
	case ModuleWAF:
		if h.wafMonitor == nil {
			return nil, fmt.Errorf("waf module is not initialized")
		}
		return h.wafMonitor.GetConfig(), nil
	case ModuleRateLimit:
		if h.rateLimitMonitor == nil {
			return nil, fmt.Errorf("rate_limit module is not initialized")
		}
		return h.rateLimitMonitor.GetConfig(), nil
	case ModuleAnomalyDetection:
		if h.anomalyDetector == nil {
			return nil, fmt.Errorf("anomaly_detection module is not initialized")
		}
		return h.anomalyDetector.GetConfig(), nil
	case ModuleGeoBlocking:
		if h.geoBlockingMgr == nil {
			return nil, fmt.Errorf("geo_blocking module is not initialized")
		}
		return h.geoBlockingMgr.GetConfig(), nil
	case ModuleIntel:
		if h.intelMgr == nil {
			return nil, fmt.Errorf("intel module is not initialized")
		}
		return h.intelMgr.GetConfig(), nil
	default:
		return nil, fmt.Errorf("unsupported module: %s", module)
	}
}

// FailGuard 动态配置请求
type failGuardConfigRequest struct {
	Enabled     *bool  `json:"enabled" validate:"omitempty"`
	MaxRetry    *int   `json:"max_retry" validate:"omitempty,gte=1,lte=1000"`
	FindTime    *int   `json:"find_time" validate:"omitempty,gte=1,lte=86400"`
	BanDuration *int   `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
	Mode        string `json:"mode" validate:"omitempty,oneof=normal ddos aggressive"`
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

	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	maxRetry := intValue(mapInt(current, "max_retry", 0), req.MaxRetry)
	findTime := intValue(mapInt(current, "find_time", 0), req.FindTime)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)
	mode := req.Mode
	if mode == "" {
		mode = mapString(current, "mode", "")
	}

	h.failguardMonitor.UpdateConfig(enabled, maxRetry, findTime, banDuration, mode)
	return nil
}

// WAF 动态配置请求
type wafConfigRequest struct {
	Enabled     *bool `json:"enabled" validate:"omitempty"`
	BanDuration *int  `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
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
	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)

	h.wafMonitor.UpdateConfig(enabled, banDuration)
	return nil
}

// RateLimit 动态配置请求
type rateLimitConfigRequest struct {
	Enabled     *bool `json:"enabled" validate:"omitempty"`
	BanDuration *int  `json:"ban_duration" validate:"omitempty,gte=1,lte=31536000"`
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
	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	banDuration := intValue(mapInt(current, "ban_duration", 0), req.BanDuration)

	h.rateLimitMonitor.UpdateConfig(enabled, banDuration)
	return nil
}

// AnomalyDetection 动态配置请求
type anomalyDetectionConfigRequest struct {
	Enabled    *bool                       `json:"enabled" validate:"omitempty"`
	MinPackets *int                        `json:"min_packets" validate:"omitempty,gte=1,lte=100000"`
	Ports      []int                       `json:"ports" validate:"omitempty,dive,gte=1,lte=65535"`
	Baseline   *anomaly.BaselineConfig     `json:"baseline" validate:"omitempty"`
	Attacks    *anomaly.AttacksConfig      `json:"attacks" validate:"omitempty"`
}

func (h *ConfigHandle) applyAnomalyDetectionConfig(raw json.RawMessage) error {
	if h.anomalyDetector == nil {
		return fmt.Errorf("anomaly_detection module is not initialized")
	}

	var req anomalyDetectionConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	// 获取当前原始结构体配置（而非 map，避免嵌套结构体类型断言失败）
	rawCfg := h.anomalyDetector.GetRawConfig()

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
	return nil
}

// GeoBlocking 动态配置请求
type geoBlockingConfigRequest struct {
	Enabled          *bool    `json:"enabled" validate:"omitempty"`
	Mode             string   `json:"mode" validate:"omitempty,oneof=allow deny"`
	AllowedCountries []string `json:"allowed_countries" validate:"omitempty,dive,len=2"`
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
	enabled := boolValue(mapBool(current, "enabled", false), req.Enabled)
	mode := req.Mode
	if mode == "" {
		mode = mapString(current, "mode", "")
	}
	countries := req.AllowedCountries
	if countries == nil {
		countries = mapStringSlice(current, "allowed_countries")
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
	currentIntel := h.intelMgr.GetConfig()
	for sourceID, srcCfg := range req.Sources {
		// 从运行时配置获取当前源的 enabled 状态作为默认值（避免意外启用已禁用的源）
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

// IsValidModule 检查模块名是否合法（导出供 DynamicConfigService 等外部调用）
func IsValidModule(module string) bool {
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

// mapBool 从 map[string]interface{} 中安全读取 bool 值
func mapBool(m map[string]interface{}, key string, fallback bool) bool {
	v, ok := m[key]
	if !ok {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

// mapInt 从 map[string]interface{} 中安全读取 int 值
func mapInt(m map[string]interface{}, key string, fallback int) int {
	v, ok := m[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return fallback
		}
		return int(i)
	default:
		return fallback
	}
}

// mapString 从 map[string]interface{} 中安全读取 string 值
func mapString(m map[string]interface{}, key string, fallback string) string {
	v, ok := m[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	return s
}

// mapStringSlice 从 map[string]interface{} 中安全读取 []string（处理 JSON round-trip 后的 []interface{} 情况）
func mapStringSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	// 直接 []string 类型
	if s, ok := v.([]string); ok {
		return s
	}
	// JSON round-trip 后变成 []interface{}
	if ifaceSlice, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(ifaceSlice))
		for _, item := range ifaceSlice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// baselineValue 如果 ptr 不为 nil 则返回 *ptr，否则从当前原始配置还原
func baselineValue(current anomaly.BaselineConfig, ptr *anomaly.BaselineConfig) anomaly.BaselineConfig {
	if ptr != nil {
		return *ptr
	}
	return current
}

// attacksValue 如果 ptr 不为 nil 则返回 *ptr，否则从当前原始配置还原
func attacksValue(current anomaly.AttacksConfig, ptr *anomaly.AttacksConfig) anomaly.AttacksConfig {
	if ptr != nil {
		return *ptr
	}
	return current
}

// validateAnomalyNestedFields 校验 anomaly 嵌套结构体中的数值字段
func validateAnomalyNestedFields(baseline *anomaly.BaselineConfig, attacks *anomaly.AttacksConfig) error {
	if baseline != nil {
		if baseline.MinSampleCount < 1 || baseline.MinSampleCount > 1000000 {
			return fmt.Errorf("baseline.min_sample_count: must be between 1 and 1000000, got %d", baseline.MinSampleCount)
		}
		if baseline.SigmaMultiplier < 1 || baseline.SigmaMultiplier > 10 {
			return fmt.Errorf("baseline.sigma_multiplier: must be between 1 and 10, got %.1f", baseline.SigmaMultiplier)
		}
		if baseline.MinThreshold < 1 || baseline.MinThreshold > 10000000 {
			return fmt.Errorf("baseline.min_threshold: must be between 1 and 10000000, got %d", baseline.MinThreshold)
		}
		if baseline.MaxAge < 60 || baseline.MaxAge > 86400*7 {
			return fmt.Errorf("baseline.max_age: must be between 60s and 7 days, got %d", baseline.MaxAge)
		}
		if baseline.BlockDuration < 1 || baseline.BlockDuration > 31536000 {
			return fmt.Errorf("baseline.block_duration: must be between 1s and 365 days, got %d", baseline.BlockDuration)
		}
	}
	if attacks != nil {
		attackConfigs := []struct {
			name   string
			config anomaly.AttackConfig
		}{
			{"syn_flood", attacks.SynFlood},
			{"udp_flood", attacks.UdpFlood},
			{"icmp_flood", attacks.IcmpFlood},
			{"ack_flood", attacks.AckFlood},
		}
		for _, ac := range attackConfigs {
			if ac.config.RatioThreshold < 0 || ac.config.RatioThreshold > 1 {
				return fmt.Errorf("attacks.%s.ratio_threshold: must be between 0 and 1, got %.2f", ac.name, ac.config.RatioThreshold)
			}
			if ac.config.BlockDuration < 1 || ac.config.BlockDuration > 31536000 {
				return fmt.Errorf("attacks.%s.block_duration: must be between 1s and 365 days, got %d", ac.name, ac.config.BlockDuration)
			}
			if ac.config.MinPackets < 0 || ac.config.MinPackets > 1000000 {
				return fmt.Errorf("attacks.%s.min_packets: must be between 0 and 1000000, got %d", ac.name, ac.config.MinPackets)
			}
		}
	}
	return nil
}

// isValidCronExpr 做基本的 cron 表达式格式校验（5段或6段，每段为合法值）
// 注意：不做完整的 cron 语义校验（如 "2月30日"），仅防止明显非法输入
func isValidCronExpr(expr string) bool {
	parts := []rune(expr)
	// 至少5个段 (分 时 日 月 周)，最多6或7个段 (含秒和/或年)
	if len(parts) < 5 || len(parts) > 20 {
		return false
	}
	// 简单检查：不能包含空格以外的控制字符
	for _, ch := range parts {
		if ch <= 0x20 && ch != ' ' && ch != '\t' {
			return false
		}
	}
	return true
}
