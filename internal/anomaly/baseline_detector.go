package anomaly

import (
	"sort"
	"time"
)

// BaselineDetector IQR 基线检测器
// 基于 PPS 历史数据计算四分位数（Q1/Q3/IQR），阈值 = Q3 + k × IQR
type BaselineDetector struct {
	config BaselineConfig
}

// UpdateConfig 热更新基线检测配置
func (d *BaselineDetector) UpdateConfig(config BaselineConfig) {
	d.config = config
}

// NewBaselineDetector 创建新的基线检测器
func NewBaselineDetector(config BaselineConfig) *BaselineDetector {
	// 设置默认值
	if config.MinSampleCount == 0 {
		config.MinSampleCount = 10
	}
	if config.IQRMultiplier == 0 {
		config.IQRMultiplier = 2.5
	}
	if config.MinThreshold == 0 {
		config.MinThreshold = 100
	}
	if config.MaxAge == 0 {
		config.MaxAge = 1800 // 默认 30 分钟
	}
	if config.BlockDuration == 0 {
		config.BlockDuration = 60
	}

	return &BaselineDetector{
		config: config,
	}
}

// UpdateBaseline 基于 PPS 历史数据更新 IQR 基线
// 只从已写入的槽位中取样本；已写入槽位中的零值是真实的空闲秒观测，必须参与统计
func (d *BaselineDetector) UpdateBaseline(baseline *Baseline, ppsHistory []uint64, windowSize int, filledCount int, ppsIndex int) {
	// 检查基线是否过期，如果过期则重置
	if d.ShouldReset(baseline) {
		d.ResetBaseline(baseline)
	}

	// 已写入槽位不足，基线未就绪
	n := filledCount
	if n > windowSize {
		n = windowSize
	}
	if n < d.config.MinSampleCount {
		return
	}

	// 从环形缓冲区中提取最近 n 个已写入的样本
	// ppsIndex 指向下一个写入点，所以最近写入的槽位是 ppsIndex-1
	samples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		idx := (ppsIndex - 1 - i + windowSize) % windowSize
		samples = append(samples, float64(ppsHistory[idx]))
	}

	// 排序后计算四分位数
	sort.Float64s(samples)

	baseline.Q1 = percentile(samples, 25)
	baseline.Q3 = percentile(samples, 75)
	baseline.IQR = baseline.Q3 - baseline.Q1
	baseline.Count = uint64(n)
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

	// 计算阈值：Q3 + k × IQR
	threshold = baseline.Q3 + d.config.IQRMultiplier*baseline.IQR

	// 如果当前值超过阈值，判定为异常
	isAnomaly = value > threshold

	return isAnomaly, threshold
}

// GetStats 获取基线统计信息
func (d *BaselineDetector) GetStats(baseline *Baseline) (q1, q3, iqr float64) {
	return baseline.Q1, baseline.Q3, baseline.IQR
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
	baseline.Q1 = 0
	baseline.Q3 = 0
	baseline.IQR = 0
	baseline.Count = 0
	baseline.LastUpdated = time.Time{}
}

// IsBaselineReady 检查基线是否准备好
func (d *BaselineDetector) IsBaselineReady(baseline *Baseline) bool {
	return baseline.Count >= uint64(d.config.MinSampleCount)
}

// percentile 计算排序后数据的指定百分位数
// 使用线性插值法（与 numpy.percentile(method='linear') 一致）
func percentile(sortedData []float64, p float64) float64 {
	n := len(sortedData)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sortedData[0]
	}

	// 计算秩（rank）
	// 对于 p 百分位，rank = (p/100) * (n-1)
	rank := (p / 100.0) * float64(n-1)

	lower := int(rank)
	upper := lower + 1
	if upper >= n {
		return sortedData[n-1]
	}

	// 线性插值
	fraction := rank - float64(lower)
	return sortedData[lower] + fraction*(sortedData[upper]-sortedData[lower])
}
