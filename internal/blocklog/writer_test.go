package blocklog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileWriter_Write(t *testing.T) {
	// 创建临时目录
	tmpDir := t.TempDir()

	// 创建文件写入器
	fw, err := NewFileWriter(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file writer: %v", err)
	}
	defer fw.Close()

	// 写入测试记录
	record := BlockRecord{
		Timestamp:   time.Now().UnixNano(),
		SrcIP:       "192.168.1.1",
		DstIP:       "10.0.0.1",
		MatchType:   "ip4_exact",
		RuleSource:  "manual",
		CountryCode: "CN",
		PacketSize:  64,
	}

	if err := fw.Write(record); err != nil {
		t.Fatalf("Failed to write record: %v", err)
	}

	// 刷新并关闭
	if err := fw.Flush(); err != nil {
		t.Fatalf("Failed to flush: %v", err)
	}

	// 检查文件是否创建
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	// 验证文件内容
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
	if readRecord.MatchType != record.MatchType {
		t.Errorf("Expected MatchType %s, got %s", record.MatchType, readRecord.MatchType)
	}
}

func TestFileWriter_HourlyRotation(t *testing.T) {
	tmpDir := t.TempDir()

	fw, err := NewFileWriter(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file writer: %v", err)
	}
	defer fw.Close()

	// 获取初始文件路径
	initialPath := fw.GetCurrentFilePath()

	// 写入一些记录
	for i := 0; i < 5; i++ {
		record := BlockRecord{
			Timestamp:  time.Now().UnixNano(),
			SrcIP:      "192.168.1.1",
			MatchType:  "ip4_exact",
			PacketSize: 64,
		}
		if err := fw.Write(record); err != nil {
			t.Fatalf("Failed to write record: %v", err)
		}
	}

	// 验证仍在同一个文件
	currentPath := fw.GetCurrentFilePath()
	if currentPath != initialPath {
		t.Errorf("File should not rotate within the same hour")
	}

	// 验证文件名格式 (YYYY-MM-DD_HH.jsonl)
	files, _ := os.ReadDir(tmpDir)
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	filename := files[0].Name()
	// 简单检查文件名格式 (YYYY-MM-DD_HH.jsonl)
	// 长度应为 19: 4(年)+1(分隔)+2(月)+1(分隔)+2(日)+1(下划线)+2(小时)+1(点)+5(.jsonl)=19
	if len(filename) != 19 || filename[4] != '-' || filename[7] != '-' || filename[10] != '_' || filename[13] != '.' {
		t.Errorf("Unexpected filename format: %s (expected pattern like YYYY-MM-DD_HH.jsonl)", filename)
	}
}

func TestFileWriter_MultipleRecords(t *testing.T) {
	tmpDir := t.TempDir()

	fw, err := NewFileWriter(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file writer: %v", err)
	}
	defer fw.Close()

	// 写入多条记录
	recordCount := 100
	for i := 0; i < recordCount; i++ {
		record := BlockRecord{
			Timestamp:  time.Now().UnixNano(),
			SrcIP:      "192.168.1.1",
			MatchType:  "ip4_exact",
			PacketSize: 64,
		}
		if err := fw.Write(record); err != nil {
			t.Fatalf("Failed to write record %d: %v", i, err)
		}
	}

	if err := fw.Flush(); err != nil {
		t.Fatalf("Failed to flush: %v", err)
	}

	// 验证记录数量
	// 使用目录中的第一个文件，因为 GetCurrentFilePath() 返回完整路径
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}
	file, err := os.Open(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	lineCount := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}

	if lineCount != recordCount {
		t.Errorf("Expected %d lines, got %d", recordCount, lineCount)
	}
}
