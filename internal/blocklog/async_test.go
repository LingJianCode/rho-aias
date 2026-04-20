package blocklog

import (
	"testing"
	"time"

	"rho-aias/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAsyncWriter_Write(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}

	config := Config{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
	}

	aw, err := NewAsyncWriter(config, testDB, nil)
	if err != nil {
		t.Fatalf("Failed to create async writer: %v", err)
	}
	defer aw.Stop()

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

	// 验证记录写入到了 SQLite 表中
	dayKey := time.Now().Format("20060102")
	tableName := "blocklog_" + dayKey
	var count int64
	testDB.Table(tableName).Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 record in table %s, got %d", tableName, count)
	}
}

func TestAsyncWriter_Stop(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}

	config := Config{
		BufferSize:    100,
		FlushInterval: time.Second,
	}

	aw, err := NewAsyncWriter(config, testDB, nil)
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

	// 验证记录已写入
	dayKey := time.Now().Format("20060102")
	tableName := "blocklog_" + dayKey
	var count int64
	testDB.Table(tableName).Count(&count)
	if count != 10 {
		t.Errorf("Expected 10 records in table %s, got %d", tableName, count)
	}
}

func TestBlockLog_WithPersistence(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	if err := testDB.AutoMigrate(&models.BlocklogHourlyStat{}, &models.BlocklogTopIP{}); err != nil {
		t.Fatalf("Failed to migrate test db: %v", err)
	}

	config := Config{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
	}

	bl, err := NewManagerWithPersistence(config, testDB)
	if err != nil {
		t.Fatalf("Failed to create block log with persistence: %v", err)
	}

	record := BlockRecord{
		Timestamp:  time.Now().UnixNano(),
		SrcIP:      "192.168.1.1",
		MatchType:  "ip4_exact",
		PacketSize: 64,
		RuleSource: "test_source",
	}
	bl.AddRecord(record)

	time.Sleep(200 * time.Millisecond)
	bl.Flush()

	if err := bl.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	// 验证记录已写入 SQLite
	dayKey := time.Now().Format("20060102")
	tableName := "blocklog_" + dayKey
	var count int64
	testDB.Table(tableName).Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 record in table %s, got %d", tableName, count)
	}
}
