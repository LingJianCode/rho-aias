package handles

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"rho-aias/internal/anomaly"
)

// ========== 值辅助函数 ==========

func boolValue(def bool, ptr *bool) bool {
	if ptr != nil { return *ptr }
	return def
}

func intValue(def int, ptr *int) int {
	if ptr != nil { return *ptr }
	return def
}

func mapBool(m map[string]interface{}, key string, fallback bool) bool {
	v, ok := m[key]; if !ok { return fallback }
	b, ok := v.(bool); if !ok { return fallback }
	return b
}

func mapInt(m map[string]interface{}, key string, fallback int) int {
	v, ok := m[key]; if !ok { return fallback }
	switch n := v.(type) {
	case int: return n
	case float64: return int(n)
	case json.Number:
		i, err := n.Int64(); if err != nil { return fallback }
		return int(i)
	default: return fallback
	}
}

func mapString(m map[string]interface{}, key string, fallback string) string {
	v, ok := m[key]; if !ok { return fallback }
	s, ok := v.(string); if !ok { return fallback }
	return s
}

func mapStringSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]; if !ok { return nil }
	if s, ok := v.([]string); ok { return s }
	if ifaceSlice, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(ifaceSlice))
		for _, item := range ifaceSlice {
			if s, ok := item.(string); ok { result = append(result, s) }
		}
		return result
	}
	return nil
}

// isNilInterface 安全的 nil 接口检查
func isNilInterface(i any) bool {
	if i == nil {
		return true
	}
	defer func() { _ = recover() }()
	return reflect.ValueOf(i).IsNil()
}

// ========== Anomaly 配置辅助函数 ==========

func baselineValue(current anomaly.BaselineConfig, ptr *anomaly.BaselineConfig) anomaly.BaselineConfig {
	if ptr != nil { return *ptr }
	return current
}

func attacksValue(current anomaly.AttacksConfig, ptr *anomaly.AttacksConfig) anomaly.AttacksConfig {
	if ptr != nil { return *ptr }
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
		attackConfigs := []struct{ name string; config anomaly.AttackConfig }{
			{"syn_flood", attacks.SynFlood}, {"udp_flood", attacks.UdpFlood},
			{"icmp_flood", attacks.IcmpFlood}, {"ack_flood", attacks.AckFlood},
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

// isValidCronExpr 基本 cron 表达式格式校验
func isValidCronExpr(expr string) bool {
	parts := strings.Fields(expr)
	return len(parts) >= 5 && len(parts) <= 7
}
