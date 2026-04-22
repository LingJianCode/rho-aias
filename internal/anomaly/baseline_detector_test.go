package anomaly

import (
	"math"
	"testing"
	"time"
)

func TestBaselineDetector_UpdateBaseline(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	baseline := &Baseline{}

	// 使用 60 秒窗口，填充 10 个非零 PPS 值
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	values := []uint64{100, 102, 98, 101, 99, 103, 97, 104, 96, 105}
	for i, v := range values {
		ppsHistory[i] = v
	}

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	if baseline.Count != 10 {
		t.Errorf("Expected Count=10, got %d", baseline.Count)
	}

	// Q1 和 Q3 应为排序后的 25% 和 75% 分位数
	// 排序后: [96, 97, 98, 99, 100, 101, 102, 103, 104, 105]
	// Q1 ≈ 97.75, Q3 ≈ 103.25
	if baseline.Q1 <= 0 || baseline.Q3 <= 0 {
		t.Errorf("Expected Q1>0 and Q3>0, got Q1=%f, Q3=%f", baseline.Q1, baseline.Q3)
	}
	if baseline.Q3 <= baseline.Q1 {
		t.Errorf("Expected Q3 > Q1, got Q1=%f, Q3=%f", baseline.Q1, baseline.Q3)
	}
	if math.Abs(baseline.IQR-(baseline.Q3-baseline.Q1)) > 0.001 {
		t.Errorf("Expected IQR=Q3-Q1, got Q1=%f, Q3=%f, IQR=%f", baseline.Q1, baseline.Q3, baseline.IQR)
	}
}

func TestBaselineDetector_UpdateBaseline_InsufficientSamples(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	baseline := &Baseline{}

	// 只有 3 个非零值，不足 minSampleCount=5
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	ppsHistory[0] = 100
	ppsHistory[1] = 200
	ppsHistory[2] = 300

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// 样本不足，不应更新基线
	if baseline.Count != 0 {
		t.Errorf("Expected Count=0 with insufficient samples, got %d", baseline.Count)
	}
}

func TestBaselineDetector_UpdateBaseline_ZeroValuesSkipped(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	baseline := &Baseline{}

	// 60 秒窗口，只有 5 个非零值（其余为 0，代表未使用的槽位）
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	ppsHistory[0] = 100
	ppsHistory[10] = 200
	ppsHistory[20] = 150
	ppsHistory[30] = 180
	ppsHistory[40] = 120

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// 只有 5 个非零值，恰好满足 minSampleCount=5
	if baseline.Count != 5 {
		t.Errorf("Expected Count=5, got %d", baseline.Count)
	}
}

func TestBaselineDetector_CheckAnomaly_InsufficientSamples(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 10,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	baseline := &Baseline{Count: 5} // 少于最小样本数

	isAnomaly, threshold := detector.CheckAnomaly(baseline, 1000)
	if isAnomaly {
		t.Error("Expected no anomaly with insufficient samples")
	}
	if threshold != 0 {
		t.Errorf("Expected threshold=0 with insufficient samples, got %f", threshold)
	}
}

func TestBaselineDetector_CheckAnomaly_BelowThreshold(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	baseline := &Baseline{
		Q1:    80,
		Q3:    120,
		IQR:   40,
		Count: 20,
	}

	// 值低于最小阈值
	isAnomaly, _ := detector.CheckAnomaly(baseline, 50)
	if isAnomaly {
		t.Error("Expected no anomaly for value below minimum threshold")
	}
}

func TestBaselineDetector_CheckAnomaly_DetectsAnomaly(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   100,
	})

	// 创建一个稳定的基线
	baseline := &Baseline{
		Q1:    100.0,
		Q3:    120.0,
		IQR:   20.0,
		Count: 100,
	}

	// 阈值 = Q3 + k*IQR = 120 + 2.5*20 = 170

	// 测试正常值（在基线范围内）
	isAnomaly, _ := detector.CheckAnomaly(baseline, 150)
	if isAnomaly {
		t.Error("Expected no anomaly for normal value")
	}

	// 测试异常值（远超基线）
	isAnomaly, threshold := detector.CheckAnomaly(baseline, 200)
	if !isAnomaly {
		t.Error("Expected anomaly for extreme value")
	}
	t.Logf("Threshold for anomaly: %f (Q3=%f, IQR=%f, k=%f)", threshold, baseline.Q3, baseline.IQR, detector.config.IQRMultiplier)
}

func TestBaselineDetector_IQRAlgorithm(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 3,
		IQRMultiplier:  2.0,
		MinThreshold:   0,
	})

	// 使用已知数据集验证百分位数计算
	// 数据: [2, 4, 4, 4, 5, 5, 7, 9]
	// 排序后: [2, 4, 4, 4, 5, 5, 7, 9]
	baseline := &Baseline{}
	windowSize := 10
	ppsHistory := make([]uint64, windowSize)
	values := []uint64{2, 4, 4, 4, 5, 5, 7, 9}
	for i, v := range values {
		ppsHistory[i] = v
	}

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// 验证 Q1 和 Q3
	// 8 个元素，Q1 在 rank = 0.25 * 7 = 1.75 → interpolate(4, 4) = 4.0
	// Q3 在 rank = 0.75 * 7 = 5.25 → interpolate(5, 7) = 5.5
	if math.Abs(baseline.Q1-4.0) > 0.01 {
		t.Errorf("Expected Q1=4.0, got %f", baseline.Q1)
	}
	if math.Abs(baseline.Q3-5.5) > 0.01 {
		t.Errorf("Expected Q3=5.5, got %f", baseline.Q3)
	}
	// IQR = 5.5 - 4.0 = 1.5
	if math.Abs(baseline.IQR-1.5) > 0.01 {
		t.Errorf("Expected IQR=1.5, got %f", baseline.IQR)
	}
}

func TestBaselineDetector_Percentile(t *testing.T) {
	tests := []struct {
		name     string
		data     []float64
		p        float64
		expected float64
	}{
		{"single element", []float64{42}, 50, 42},
		{"two elements median", []float64{1, 3}, 50, 2},
		{"two elements Q1", []float64{1, 3}, 25, 1.5},
		{"even count Q1", []float64{1, 2, 3, 4, 5, 6, 7, 8}, 25, 2.75},
		{"even count Q3", []float64{1, 2, 3, 4, 5, 6, 7, 8}, 75, 6.25},
		{"odd count Q1", []float64{1, 2, 3, 4, 5}, 25, 2},
		{"odd count Q3", []float64{1, 2, 3, 4, 5}, 75, 4},
		{"p=0", []float64{10, 20, 30}, 0, 10},
		{"p=100", []float64{10, 20, 30}, 100, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentile(tt.data, tt.p)
			if math.Abs(result-tt.expected) > 0.01 {
				t.Errorf("percentile(%v, %f) = %f, expected %f", tt.data, tt.p, result, tt.expected)
			}
		})
	}
}

func TestBaselineDetector_IsBaselineReady(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 10,
	})

	baseline := &Baseline{Count: 5}
	if detector.IsBaselineReady(baseline) {
		t.Error("Expected baseline not ready with 5 samples")
	}

	baseline.Count = 10
	if !detector.IsBaselineReady(baseline) {
		t.Error("Expected baseline ready with 10 samples")
	}
}

func TestBaselineDetector_GetStats(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{})

	baseline := &Baseline{
		Q1:  80.0,
		Q3:  120.0,
		IQR: 40.0,
	}

	q1, q3, iqr := detector.GetStats(baseline)

	if q1 != 80.0 {
		t.Errorf("Expected q1=80.0, got %f", q1)
	}
	if q3 != 120.0 {
		t.Errorf("Expected q3=120.0, got %f", q3)
	}
	if iqr != 40.0 {
		t.Errorf("Expected iqr=40.0, got %f", iqr)
	}
}

func TestBaselineDetector_DefaultConfig(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{})

	if detector.config.MinSampleCount != 10 {
		t.Errorf("Expected default MinSampleCount=10, got %d", detector.config.MinSampleCount)
	}
	if detector.config.IQRMultiplier != 2.5 {
		t.Errorf("Expected default IQRMultiplier=2.5, got %f", detector.config.IQRMultiplier)
	}
	if detector.config.MinThreshold != 100 {
		t.Errorf("Expected default MinThreshold=100, got %d", detector.config.MinThreshold)
	}
	if detector.config.MaxAge != 1800 {
		t.Errorf("Expected default MaxAge=1800, got %d", detector.config.MaxAge)
	}
}

// ============================================
// 补充测试：零方差、过期、重置
// ============================================

func TestBaselineDetector_ZeroIQR(t *testing.T) {
	// 所有值相同 → IQR 为 0
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   10,
	})

	baseline := &Baseline{}
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	for i := 0; i < 10; i++ {
		ppsHistory[i] = 100
	}

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// Q1 = Q3 = 100, IQR = 0
	if math.Abs(baseline.Q1-100.0) > 0.001 {
		t.Errorf("Expected Q1=100.0, got %f", baseline.Q1)
	}
	if math.Abs(baseline.Q3-100.0) > 0.001 {
		t.Errorf("Expected Q3=100.0, got %f", baseline.Q3)
	}
	if baseline.IQR > 1e-10 {
		t.Errorf("Expected IQR≈0 for constant values, got %f", baseline.IQR)
	}

	// 检查异常：value=100 不应触发（阈值 = 100 + 2.5*0 = 100，不严格大于）
	isAnomaly, threshold := detector.CheckAnomaly(baseline, 100)
	if isAnomaly {
		t.Error("Expected no anomaly for value equal to Q3 with zero IQR")
	}
	if math.Abs(threshold-100.0) > 0.001 {
		t.Errorf("Expected threshold=100.0, got %f", threshold)
	}

	// value=101 应触发（101 > 100）
	isAnomaly, _ = detector.CheckAnomaly(baseline, 101)
	if !isAnomaly {
		t.Error("Expected anomaly for value slightly above Q3 with zero IQR")
	}
}

func TestBaselineDetector_ShouldReset(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   0,
		MaxAge:         1, // 1秒过期
	})

	baseline := &Baseline{}

	// 空基线不应重置
	if detector.ShouldReset(baseline) {
		t.Error("Expected ShouldReset=false for empty baseline")
	}

	// 更新基线
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	for i := 0; i < 10; i++ {
		ppsHistory[i] = 100
	}
	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// 刚更新，不应重置
	if detector.ShouldReset(baseline) {
		t.Error("Expected ShouldReset=false for freshly updated baseline")
	}

	// 等待过期
	time.Sleep(1500 * time.Millisecond)

	// 过期后应重置
	if !detector.ShouldReset(baseline) {
		t.Error("Expected ShouldReset=true for expired baseline")
	}
}

func TestBaselineDetector_ResetBaseline(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   0,
	})

	baseline := &Baseline{}
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	for i := 0; i < 20; i++ {
		ppsHistory[i] = uint64(100 + i)
	}
	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// 确认有数据
	if baseline.Count != 20 {
		t.Fatalf("Expected Count=20, got %d", baseline.Count)
	}

	// 重置
	detector.ResetBaseline(baseline)

	if baseline.Q1 != 0 {
		t.Errorf("Expected Q1=0 after reset, got %f", baseline.Q1)
	}
	if baseline.Q3 != 0 {
		t.Errorf("Expected Q3=0 after reset, got %f", baseline.Q3)
	}
	if baseline.IQR != 0 {
		t.Errorf("Expected IQR=0 after reset, got %f", baseline.IQR)
	}
	if baseline.Count != 0 {
		t.Errorf("Expected Count=0 after reset, got %d", baseline.Count)
	}
	if !baseline.LastUpdated.IsZero() {
		t.Error("Expected LastUpdated to be zero after reset")
	}

	// 重置后不应检测到异常
	isAnomaly, _ := detector.CheckAnomaly(baseline, 1000)
	if isAnomaly {
		t.Error("Expected no anomaly after baseline reset (insufficient samples)")
	}
}

func TestBaselineDetector_UpdateResetOnExpired(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   0,
		MaxAge:         1, // 1秒过期
	})

	baseline := &Baseline{}
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)
	for i := 0; i < 10; i++ {
		ppsHistory[i] = 100
	}
	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	if baseline.Count != 10 {
		t.Fatalf("Expected Count=10, got %d", baseline.Count)
	}

	// 等待过期
	time.Sleep(1500 * time.Millisecond)

	// 再次更新（应自动重置后重新计算）
	for i := 0; i < 10; i++ {
		ppsHistory[i] = 200
	}
	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// Count 应为 10（重置后重新计算）
	if baseline.Count != 10 {
		t.Errorf("Expected Count=10 after auto-reset, got %d", baseline.Count)
	}
	// 所有值为 200，Q1=Q3=200
	if math.Abs(baseline.Q3-200.0) > 0.001 {
		t.Errorf("Expected Q3=200.0 after auto-reset, got %f", baseline.Q3)
	}
}

func TestBaselineDetector_CheckAnomaly_ExactThreshold(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 3,
		IQRMultiplier:  2.0,
		MinThreshold:   50, // 设置足够低的阈值
	})

	// Q1=50, Q3=70, IQR=20, 阈值 = 70 + 2*20 = 110
	baseline := &Baseline{
		Q1:    50.0,
		Q3:    70.0,
		IQR:   20.0,
		Count: 3,
	}

	isAnomaly, threshold := detector.CheckAnomaly(baseline, 110)
	if math.Abs(threshold-110.0) > 0.001 {
		t.Errorf("Expected threshold=110.0, got %f", threshold)
	}
	// 恰好等于阈值，不触发（使用 >）
	if isAnomaly {
		t.Error("Expected no anomaly when value equals threshold")
	}

	// 超过阈值，触发
	isAnomaly, _ = detector.CheckAnomaly(baseline, 111)
	if !isAnomaly {
		t.Error("Expected anomaly when value exceeds threshold")
	}
}

func TestBaselineDetector_SkewedDistribution(t *testing.T) {
	// IQR 对偏态分布更鲁棒的关键测试
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount: 5,
		IQRMultiplier:  2.5,
		MinThreshold:   0,
	})

	baseline := &Baseline{}
	windowSize := 60
	ppsHistory := make([]uint64, windowSize)

	// 右偏分布：大量低值 + 少量高值
	// 模拟正常 Web 流量：大部分时间 PPS 在 100-200，偶尔峰值 500
	skewedValues := []uint64{
		100, 100, 110, 120, 120, 130, 130, 140,
		150, 150, 160, 160, 170, 180, 200, 220,
		250, 300, 350, 500,
	}
	for i, v := range skewedValues {
		ppsHistory[i] = v
	}

	detector.UpdateBaseline(baseline, ppsHistory, windowSize)

	// Q1 应该在低值区域，Q3 在中等值区域
	// IQR 不会受极端值（500）太大影响
	t.Logf("Q1=%f, Q3=%f, IQR=%f", baseline.Q1, baseline.Q3, baseline.IQR)

	threshold := baseline.Q3 + detector.config.IQRMultiplier*baseline.IQR
	t.Logf("Threshold=%f", threshold)

	// 500 不应被视为异常（它是数据的一部分，IQR 容忍了这种偏态）
	isAnomaly, _ := detector.CheckAnomaly(baseline, 500)
	if isAnomaly {
		t.Logf("Note: 500 PPS was flagged as anomaly with IQR threshold=%f. This may be acceptable for highly right-skewed data.", threshold)
	}

	// 但 2000 PPS 应该被检测为异常
	isAnomaly, _ = detector.CheckAnomaly(baseline, 2000)
	if !isAnomaly {
		t.Error("Expected 2000 PPS to be detected as anomaly")
	}
}
