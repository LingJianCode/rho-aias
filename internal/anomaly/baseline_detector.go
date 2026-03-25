package anomaly

import (
	"math"
	"time"
)

// BaselineDetector 3σ 基线检测器
// 使用 Welford 算法进行在线学习
type BaselineDetector struct {
	config BaselineConfig
}

// NewBaselineDetector 创建新的基线检测器
func NewBaselineDetector(config BaselineConfig) *BaselineDetector {
	// 设置默认值
	if config.MinSampleCount == 0 {
		config.MinSampleCount = 10
	}
	if config.SigmaMultiplier == 0 {
		config.SigmaMultiplier = 3.0
	}
	if config.MinThreshold == 0 {
		config.MinThreshold = 100
	}
	if config.MaxAge == 0 {
		config.MaxAge = 1800 // 默认 30 分钟
	}

	return &BaselineDetector{
		config: config,
	}
}

// UpdateBaseline 使用 Welford 算法更新基线
// Welford 算法是一种在线算法，可以逐步更新均值和方差，避免二次遍历
// 公式：
//   - μ_new = μ_old + (x - μ_old) / n
//   - M2_new = M2_old + (x - μ_old) * (x - μ_new)
//   - σ² = M2 / (n - 1)  (当 n > 1)
func (d *BaselineDetector) UpdateBaseline(baseline *Baseline, value float64) {
	// 检查基线是否过期，如果过期则重置
	if d.ShouldReset(baseline) {
		d.ResetBaseline(baseline)
	}

	baseline.Count++
	n := float64(baseline.Count)

	// Welford 算法更新均值和 M2
	delta := value - baseline.Mean
	baseline.Mean += delta / n
	delta2 := value - baseline.Mean
	baseline.M2 += delta * delta2

	// 更新最后修改时间
	baseline.LastUpdated = time.Now()
}

// CheckAnomaly 检查是否为异常
// 返回值：是否异常、当前阈值
func (d *BaselineDetector) CheckAnomaly(baseline *Baseline, value float64) (isAnomaly bool, threshold float64) {
	// 样本数不足，不检测
	if baseline.Count < uint64(d.config.MinSampleCount) {
		return false, 0
	}

	// 低于最小阈值，不检测
	if value < float64(d.config.MinThreshold) {
		return false, 0
	}

	// 计算标准差
	var stdDev float64
	if baseline.Count > 1 {
		variance := baseline.M2 / float64(baseline.Count-1)
		stdDev = math.Sqrt(variance)
	}

	// 计算阈值：μ + kσ
	threshold = baseline.Mean + d.config.SigmaMultiplier*stdDev

	// 如果当前值超过阈值，判定为异常
	isAnomaly = value > threshold

	return isAnomaly, threshold
}

// GetStats 获取基线统计信息
func (d *BaselineDetector) GetStats(baseline *Baseline) (mean, stdDev float64) {
	mean = baseline.Mean
	if baseline.Count > 1 {
		variance := baseline.M2 / float64(baseline.Count-1)
		stdDev = math.Sqrt(variance)
	}
	return mean, stdDev
}

// ShouldReset 检查是否应该重置基线
// 如果基线超过最大年龄（MaxAge），应该重置
func (d *BaselineDetector) ShouldReset(baseline *Baseline) bool {
	if baseline.Count == 0 {
		return false
	}
	maxAge := time.Duration(d.config.MaxAge) * time.Second
	return time.Since(baseline.LastUpdated) > maxAge
}

// ResetBaseline 重置基线数据
func (d *BaselineDetector) ResetBaseline(baseline *Baseline) {
	baseline.Mean = 0
	baseline.M2 = 0
	baseline.Count = 0
	baseline.LastUpdated = time.Time{}
}

// IsBaselineReady 检查基线是否准备好
func (d *BaselineDetector) IsBaselineReady(baseline *Baseline) bool {
	return baseline.Count >= uint64(d.config.MinSampleCount)
}
