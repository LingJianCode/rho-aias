package anomaly

import (
	"math"
	"testing"
	"time"
)

func TestBaselineDetector_UpdateBaseline(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  10,
		SigmaMultiplier: 3.0,
		MinThreshold:    100,
	})

	baseline := &Baseline{}

	// 测试 Welford 算法更新
	values := []float64{100, 102, 98, 101, 99, 103, 97, 104, 96, 105}
	for _, v := range values {
		detector.UpdateBaseline(baseline, v)
	}

	if baseline.Count != 10 {
		t.Errorf("Expected Count=10, got %d", baseline.Count)
	}

	// 验证均值接近 100.5
	expectedMean := 100.5
	if math.Abs(baseline.Mean-expectedMean) > 1.0 {
		t.Errorf("Mean %f is too far from expected %f", baseline.Mean, expectedMean)
	}
}

func TestBaselineDetector_CheckAnomaly_InsufficientSamples(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  10,
		SigmaMultiplier: 3.0,
		MinThreshold:    100,
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
		MinSampleCount:  10,
		SigmaMultiplier: 3.0,
		MinThreshold:    100,
	})

	baseline := &Baseline{
		Mean:  50,
		M2:    100,
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
		MinSampleCount:  10,
		SigmaMultiplier: 3.0,
		MinThreshold:    100,
	})

	// 创建一个稳定的基线（均值=100，标准差≈10）
	baseline := &Baseline{
		Mean:  100.0,
		M2:    1000.0, // 方差 = M2 / (n-1) = 1000/99 ≈ 10.1, 标准差 ≈ 3.18
		Count: 100,
	}

	// 测试正常值（在基线范围内）
	isAnomaly, _ := detector.CheckAnomaly(baseline, 105)
	if isAnomaly {
		t.Error("Expected no anomaly for normal value")
	}

	// 测试异常值（远超基线）
	isAnomaly, threshold := detector.CheckAnomaly(baseline, 200)
	if !isAnomaly {
		t.Error("Expected anomaly for extreme value")
	}
	t.Logf("Threshold for anomaly: %f", threshold)
}

func TestBaselineDetector_WelfordAlgorithm(t *testing.T) {
	// 测试 Welford 算法的数值稳定性
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  3,
		SigmaMultiplier: 2.0,
		MinThreshold:    0,
	})

	// 使用已知数据集验证算法
	// 数据: [2, 4, 4, 4, 5, 5, 7, 9]
	// 均值: 5, 标准差: 2
	baseline := &Baseline{}
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}

	for _, v := range values {
		detector.UpdateBaseline(baseline, v)
	}

	// 验证均值
	if math.Abs(baseline.Mean-5.0) > 0.001 {
		t.Errorf("Expected Mean=5.0, got %f", baseline.Mean)
	}

	// 验证标准差
	// 方差 = M2 / (n-1) = 32 / 7 ≈ 4.57
	// 标准差 = sqrt(4.57) ≈ 2.14
	expectedVariance := 32.0 / 7.0
	actualVariance := baseline.M2 / float64(baseline.Count-1)
	if math.Abs(actualVariance-expectedVariance) > 0.001 {
		t.Errorf("Expected variance=%f, got %f", expectedVariance, actualVariance)
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
		Mean:  100.0,
		M2:    100.0,
		Count: 2,
	}

	mean, stdDev := detector.GetStats(baseline)

	if mean != 100.0 {
		t.Errorf("Expected mean=100.0, got %f", mean)
	}

	// 标准差 = sqrt(M2 / (n-1)) = sqrt(100 / 1) = 10
	expectedStdDev := 10.0
	if math.Abs(stdDev-expectedStdDev) > 0.001 {
		t.Errorf("Expected stdDev=%f, got %f", expectedStdDev, stdDev)
	}
}

func TestBaselineDetector_DefaultConfig(t *testing.T) {
	// 测试默认配置
	detector := NewBaselineDetector(BaselineConfig{})

	if detector.config.MinSampleCount != 10 {
		t.Errorf("Expected default MinSampleCount=10, got %d", detector.config.MinSampleCount)
	}
	if detector.config.SigmaMultiplier != 3.0 {
		t.Errorf("Expected default SigmaMultiplier=3.0, got %f", detector.config.SigmaMultiplier)
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

func TestBaselineDetector_ZeroVariance(t *testing.T) {
	// 所有值相同 → 方差为 0，标准差为 0
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  5,
		SigmaMultiplier: 3.0,
		MinThreshold:    10,
	})

	baseline := &Baseline{}
	for i := 0; i < 10; i++ {
		detector.UpdateBaseline(baseline, 100.0)
	}

	// 均值应为 100
	if math.Abs(baseline.Mean-100.0) > 0.001 {
		t.Errorf("Expected Mean=100.0, got %f", baseline.Mean)
	}

	// M2 应接近 0（数值精度范围内）
	if baseline.M2 > 1e-10 {
		t.Errorf("Expected M2≈0 for constant values, got %f", baseline.M2)
	}

	// 检查异常：value=100 不应触发（阈值 = 100 + 3*0 = 100，不严格大于）
	isAnomaly, threshold := detector.CheckAnomaly(baseline, 100)
	if isAnomaly {
		t.Error("Expected no anomaly for value equal to mean with zero variance")
	}
	if math.Abs(threshold-100.0) > 0.001 {
		t.Errorf("Expected threshold=100.0, got %f", threshold)
	}

	// value=101 应触发（101 > 100）
	isAnomaly, _ = detector.CheckAnomaly(baseline, 101)
	if !isAnomaly {
		t.Error("Expected anomaly for value slightly above mean with zero variance")
	}
}

func TestBaselineDetector_ShouldReset(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  5,
		SigmaMultiplier: 3.0,
		MinThreshold:    0,
		MaxAge:          1, // 1秒过期
	})

	baseline := &Baseline{}

	// 空基线不应重置
	if detector.ShouldReset(baseline) {
		t.Error("Expected ShouldReset=false for empty baseline")
	}

	// 更新基线
	detector.UpdateBaseline(baseline, 100.0)

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
		MinSampleCount:  5,
		SigmaMultiplier: 3.0,
		MinThreshold:    0,
	})

	baseline := &Baseline{}
	// 填充数据
	for i := 0; i < 20; i++ {
		detector.UpdateBaseline(baseline, float64(100+i))
	}

	// 确认有数据
	if baseline.Count != 20 {
		t.Fatalf("Expected Count=20, got %d", baseline.Count)
	}

	// 重置
	detector.ResetBaseline(baseline)

	if baseline.Mean != 0 {
		t.Errorf("Expected Mean=0 after reset, got %f", baseline.Mean)
	}
	if baseline.M2 != 0 {
		t.Errorf("Expected M2=0 after reset, got %f", baseline.M2)
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
		MinSampleCount:  5,
		SigmaMultiplier: 3.0,
		MinThreshold:    0,
		MaxAge:          1, // 1秒过期
	})

	baseline := &Baseline{}
	// 建立基线
	for i := 0; i < 10; i++ {
		detector.UpdateBaseline(baseline, 100.0)
	}

	if baseline.Count != 10 {
		t.Fatalf("Expected Count=10, got %d", baseline.Count)
	}

	// 等待过期
	time.Sleep(1500 * time.Millisecond)

	// 再次更新（应自动重置后重新计算）
	detector.UpdateBaseline(baseline, 200.0)

	// Count 应为 1（重置后重新开始）
	if baseline.Count != 1 {
		t.Errorf("Expected Count=1 after auto-reset, got %d", baseline.Count)
	}
	// Mean 应为 200.0
	if math.Abs(baseline.Mean-200.0) > 0.001 {
		t.Errorf("Expected Mean=200.0 after auto-reset, got %f", baseline.Mean)
	}
}

func TestBaselineDetector_CheckAnomaly_ExactThreshold(t *testing.T) {
	detector := NewBaselineDetector(BaselineConfig{
		MinSampleCount:  3,
		SigmaMultiplier: 2.0,
		MinThreshold:    50, // 设置足够低的阈值
	})

	// 均值=50, 方差=M2/(n-1), 用固定基线
	baseline := &Baseline{
		Mean:  50.0,
		M2:    200.0, // 方差 = 200/2 = 100, 标准差 = 10
		Count: 3,
	}

	// 阈值 = 50 + 2*10 = 70
	isAnomaly, threshold := detector.CheckAnomaly(baseline, 70)
	if threshold != 70.0 {
		t.Errorf("Expected threshold=70.0, got %f", threshold)
	}
	// 恰好等于阈值，不触发（使用 >）
	if isAnomaly {
		t.Error("Expected no anomaly when value equals threshold")
	}

	// 超过阈值，触发
	isAnomaly, _ = detector.CheckAnomaly(baseline, 71)
	if !isAnomaly {
		t.Error("Expected anomaly when value exceeds threshold")
	}
}
