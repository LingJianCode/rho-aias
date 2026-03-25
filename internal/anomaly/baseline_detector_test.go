package anomaly

import (
	"math"
	"testing"
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
