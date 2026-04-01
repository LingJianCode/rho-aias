package blocklog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAsyncWriter_Write(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		Enabled:         true,
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
	}

	aw, err := NewAsyncWriter(config)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}
	defer func() {
		if err := aw.Stop(); err != nil {
			t.Logf("aw.Stop() error: %v", err)
		}
	}()

	// 写入测试记录
	record := BlockRecord{
		Timestamp:  time.Now().UnixNano(),
		SrcIP:      "192.168.1.1",
		MatchType:  "ip4_exact",
		PacketSize: 64,
	}

	if err := aw.Write(record); err != nil {
		t.Fatalf("Failed to write record: %v", err)
	}

	// 等待写入完成
	time.Sleep(200 * time.Millisecond)

	// 手动刷新
	aw.Flush()

	// 验证文件
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	// 验证内容
	file, err := os.Open(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("Failed to read line from file")
	}

	var readRecord BlockRecord
	if err := json.Unmarshal(scanner.Bytes(), &readRecord); err != nil {
		t.Fatalf("Failed to unmarshal record: %v", err)
	}

	if readRecord.SrcIP != record.SrcIP {
		t.Errorf("Expected SrcIP %s, got %s", record.SrcIP, readRecord.SrcIP)
	}
}

func TestAsyncWriter_Stop(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		Enabled:         true,
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      100, // 增大缓冲区以防止记录被丢弃
		FlushInterval:   time.Second,
	}

	aw, err := NewAsyncWriter(config)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}

	// 写入一些记录
	for i := 0; i < 10; i++ {
		record := BlockRecord{
			Timestamp:  time.Now().UnixNano(),
			SrcIP:      "192.168.1.1",
			MatchType:  "ip4_exact",
			PacketSize: 64,
		}
		if err := aw.Write(record); err != nil {
			t.Logf("aw.Write() error: %v", err)
		}
	}

	// 等待一下让写入协程处理记录
	time.Sleep(100 * time.Millisecond)

	// 停止应该等待所有记录写入
	if err := aw.Stop(); err != nil {
		t.Fatalf("Failed to stop: %v", err)
	}

	// 验证文件
	files, _ := os.ReadDir(tmpDir)
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	// 计算行数
	file, _ := os.Open(filepath.Join(tmpDir, files[0].Name()))
	defer file.Close()

	lineCount := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}

	if lineCount != 10 {
		t.Errorf("Expected 10 lines, got %d", lineCount)
	}
}

func TestAsyncWriter_Disabled(t *testing.T) {
	config := Config{
		Enabled: false,
	}

	aw, err := NewAsyncWriter(config)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}

	// 禁用时不应该做任何操作
	record := BlockRecord{SrcIP: "192.168.1.1"}
	if err := aw.Write(record); err != nil {
		t.Fatalf("Write should succeed when disabled: %v", err)
	}

	// Stop 应该安全返回
	if err := aw.Stop(); err != nil {
		t.Fatalf("Stop should succeed when disabled: %v", err)
	}
}

func TestBlockLog_WithPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		Enabled:         true,
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
	}

	bl, err := NewBlockLogWithPersistence(100, config)
	if err != nil {
		t.Fatalf("Failed to create block log with persistence: %v", err)
	}

	// 添加记录
	record := BlockRecord{
		Timestamp:  time.Now().UnixNano(),
		SrcIP:      "192.168.1.1",
		MatchType:  "ip4_exact",
		PacketSize: 64,
	}
	bl.AddRecord(record)

	// 验证内存中有记录
	if bl.Count() != 1 {
		t.Errorf("Expected 1 record in memory, got %d", bl.Count())
	}

	// 等待异步写入
	time.Sleep(200 * time.Millisecond)
	bl.Flush()

	// 关闭
	if err := bl.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	// 验证文件
	files, _ := os.ReadDir(tmpDir)
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}
}
