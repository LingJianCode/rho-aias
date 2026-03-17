// Package threatintel 威胁情报模块
package threatintel

import (
	"testing"

	"rho-aias/internal/ebpfs"
)

// TestDiffLogic 测试 diff 函数的按位删除逻辑
func TestDiffLogic(t *testing.T) {
	syncer := &Syncer{}

	tests := []struct {
		name           string
		current        []ebpfs.Rule
		newData        *IntelData
		sourceMask     uint32
		expectAdd      int
		expectRemove   int
		expectUpdate   int
	}{
		{
			name: "单源规则删除",
			current: []ebpfs.Rule{
				{Key: "1.2.3.4", Value: ebpfs.NewBlockValue(0x01)}, // 仅 IPSum
			},
			newData:      &IntelData{}, // 空数据，需要删除
			sourceMask:   0x01,         // IPSum
			expectAdd:    0,
			expectRemove: 1,
			expectUpdate: 0,
		},
		{
			name: "多源规则按位删除",
			current: []ebpfs.Rule{
				{Key: "1.2.3.4", Value: ebpfs.BlockValue{SourceMask: 0x03}}, // IPSum + Spamhaus
				{Key: "5.6.7.8", Value: ebpfs.NewBlockValue(0x01)},          // 仅 IPSum
			},
			newData:      &IntelData{}, // 空数据，需要删除
			sourceMask:   0x01,         // IPSum
			expectAdd:    0,
			expectRemove: 1,          // 5.6.7.8 单源，直接删除
			expectUpdate: 1,          // 1.2.3.4 多源，按位删除
		},
		{
			name: "多源规则保留其他来源",
			current: []ebpfs.Rule{
				{Key: "1.2.3.4", Value: ebpfs.BlockValue{SourceMask: 0x03}}, // IPSum + Spamhaus
			},
			newData:      &IntelData{}, // 空数据
			sourceMask:   0x01,         // IPSum
			expectAdd:    0,
			expectRemove: 0, // 不直接删除，因为是多源
			expectUpdate: 1, // 按位删除 IPSum
		},
		{
			name:    "新增规则",
			current: []ebpfs.Rule{}, // 空内核
			newData: &IntelData{
				IPv4Exact: []string{"1.2.3.4", "5.6.7.8"},
			},
			sourceMask:   0x01,
			expectAdd:    2,
			expectRemove: 0,
			expectUpdate: 0,
		},
		{
			name: "混合场景",
			current: []ebpfs.Rule{
				{Key: "1.2.3.4", Value: ebpfs.BlockValue{SourceMask: 0x03}}, // 多源，需按位删除
				{Key: "5.6.7.8", Value: ebpfs.NewBlockValue(0x01)},          // 单源，需删除
				{Key: "9.10.11.12", Value: ebpfs.NewBlockValue(0x01)},       // 保留
			},
			newData: &IntelData{
				IPv4Exact: []string{"9.10.11.12", "13.14.15.16"}, // 保留 + 新增
			},
			sourceMask:   0x01,
			expectAdd:    1, // 13.14.15.16
			expectRemove: 1, // 5.6.7.8
			expectUpdate: 1, // 1.2.3.4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toAdd, toRemove, toUpdateMask := syncer.diff(tt.current, tt.newData, tt.sourceMask)

			if len(toAdd) != tt.expectAdd {
				t.Errorf("toAdd: got %d, want %d", len(toAdd), tt.expectAdd)
			}
			if len(toRemove) != tt.expectRemove {
				t.Errorf("toRemove: got %d, want %d", len(toRemove), tt.expectRemove)
			}
			if len(toUpdateMask) != tt.expectUpdate {
				t.Errorf("toUpdateMask: got %d, want %d", len(toUpdateMask), tt.expectUpdate)
			}
		})
	}
}

// TestSourceMask 按位操作测试
func TestSourceMask(t *testing.T) {
	tests := []struct {
		name       string
		oldMask    uint32
		removeMask uint32
		expectNew  uint32
	}{
		{
			name:       "移除单源",
			oldMask:    0x01, // IPSum
			removeMask: 0x01,
			expectNew:  0x00,
		},
		{
			name:       "多源移除其中一个",
			oldMask:    0x03, // IPSum + Spamhaus
			removeMask: 0x01, // 移除 IPSum
			expectNew:  0x02, // 剩余 Spamhaus
		},
		{
			name:       "多源移除另一个",
			oldMask:    0x03, // IPSum + Spamhaus
			removeMask: 0x02, // 移除 Spamhaus
			expectNew:  0x01, // 剩余 IPSum
		},
		{
			name:       "移除不存在的源",
			oldMask:    0x01, // IPSum
			removeMask: 0x02, // 尝试移除 Spamhaus
			expectNew:  0x01, // 保持不变
		},
		{
			name:       "三源移除中间",
			oldMask:    0x07, // IPSum + Spamhaus + Manual
			removeMask: 0x02, // 移除 Spamhaus
			expectNew:  0x05, // 剩余 IPSum + Manual
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newMask := tt.oldMask &^ tt.removeMask
			if newMask != tt.expectNew {
				t.Errorf("mask operation: got 0x%02x, want 0x%02x", newMask, tt.expectNew)
			}
		})
	}
}
