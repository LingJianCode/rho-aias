package geoblocking

import (
	"fmt"
	"net"
	"sync"

	"rho-aias/internal/logger"

	"github.com/oschwald/maxminddb-golang"
)

// MMDBReader 封装 maxminddb.Reader，支持热更新
type MMDBReader struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
}

// NewMMDBReader 创建新的 MMDBReader
func NewMMDBReader() *MMDBReader {
	return &MMDBReader{}
}

// Load 从字节数据加载 MMDB（首次加载或热更新）
func (r *MMDBReader) Load(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty mmdb data")
	}

	newReader, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("open mmdb from bytes failed: %w", err)
	}

	r.mu.Lock()
	oldReader := r.reader
	r.reader = newReader
	r.mu.Unlock()

	// 关闭旧 reader
	if oldReader != nil {
		_ = oldReader.Close()
	}

	logger.Info("[MMDBReader] MMDB loaded successfully")
	return nil
}

// LookupCountry 查询 IP 的国家代码
func (r *MMDBReader) LookupCountry(ipStr string) (string, error) {
	r.mu.RLock()
	reader := r.reader
	r.mu.RUnlock()

	if reader == nil {
		return "", fmt.Errorf("mmdb not loaded")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid ip: %s", ipStr)
	}

	var record struct {
		Country struct {
			IsoCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			IsoCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}

	if err := reader.Lookup(ip, &record); err != nil {
		return "", fmt.Errorf("lookup failed for %s: %w", ipStr, err)
	}

	if record.Country.IsoCode != "" {
		return record.Country.IsoCode, nil
	}
	if record.RegisteredCountry.IsoCode != "" {
		return record.RegisteredCountry.IsoCode, nil
	}

	return "", nil
}

// Close 关闭 MMDBReader
func (r *MMDBReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reader != nil {
		err := r.reader.Close()
		r.reader = nil
		return err
	}
	return nil
}
