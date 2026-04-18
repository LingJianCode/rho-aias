package blocklog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rho-aias/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAsyncWriter_Write(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
	}

	aw, err := NewAsyncWriter(config, nil)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}
	defer func() {
		if err := aw.Stop(); err != nil {
			t.Logf("aw.Stop() error: %v", err)
		}
	}()

	record := BlockRecord{
		Timestamp:  time.Now().UnixNano(),
		SrcIP:      "192.168.1.1",
		MatchType:  "ip4_exact",
		PacketSize: 64,
	}

	if err := aw.Write(record); err != nil {
		t.Fatalf("Failed to write record: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	aw.Flush()

	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

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
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      100,
		FlushInterval:   time.Second,
	}

	aw, err := NewAsyncWriter(config, nil)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}

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

	time.Sleep(100 * time.Millisecond)

	if err := aw.Stop(); err != nil {
		t.Fatalf("Failed to stop: %v", err)
	}

	files, _ := os.ReadDir(tmpDir)
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

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

func TestBlockLog_WithPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogDir:          tmpDir,
		MemoryCacheSize: 100,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
	}

	bl, err := NewManagerWithPersistence(100, config, nil)
	if err != nil {
		t.Fatalf("Failed to create block log with persistence: %v", err)
	}

	// 注入内存中的 GORM SQLite 连接
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	if err := testDB.AutoMigrate(&models.BlocklogHourlyStat{}, &models.BlocklogTopIP{}); err != nil {
		t.Fatalf("Failed to migrate test db: %v", err)
	}
	bl.statsStore = NewStatsStore(testDB)

	record := BlockRecord{
		Timestamp:  time.Now().UnixNano(),
		SrcIP:      "192.168.1.1",
		MatchType:  "ip4_exact",
		PacketSize: 64,
		RuleSource: "test_source",
	}
	bl.AddRecord(record)

	if bl.Count() != 1 {
		t.Errorf("Expected 1 record in memory, got %d", bl.Count())
	}

	time.Sleep(200 * time.Millisecond)
	bl.Flush()

	if err := bl.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	files, _ := os.ReadDir(tmpDir)
	var logFileFound bool
	if len(files) > 0 {
		f := files[0]
		if f.Name() == "blocklog_stats.db" {
			t.Errorf("StatsStore should not create its own database file anymore, but found: %s", f.Name())
		}
		logFileFound = true

		file, err := os.Open(filepath.Join(tmpDir, f.Name()))
		if err != nil {
			t.Fatalf("Failed to open log file %s: %v", f.Name(), err)
		}

		scanner := bufio.NewScanner(file)
		if !scanner.Scan() {
			file.Close()
			t.Fatalf("Failed to read line from log file")
		}

		var readRecord BlockRecord
		if err := json.Unmarshal(scanner.Bytes(), &readRecord); err != nil {
			file.Close()
			t.Fatalf("Failed to unmarshal record: %v", err)
		}
		file.Close()

		if readRecord.SrcIP != record.SrcIP {
			t.Errorf("Expected SrcIP %s, got %s", record.SrcIP, readRecord.SrcIP)
		}
	}

	if !logFileFound {
		t.Error("Expected to find a log file, but none found")
	}
}
