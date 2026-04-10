// Package source 提供威胁情报和地域封禁等数据源模块的公共基础设施
package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Fetcher 通用的 HTTP 数据获取器
// 负责从外部 URL 获取数据（被 ThreatIntel、GeoBlocking 等模块复用）
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
}

// NewFetcher 创建新的数据获取器
func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// Fetch 从指定 URL 获取数据，返回原始字节数据
func (f *Fetcher) Fetch(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	return data, nil
}
