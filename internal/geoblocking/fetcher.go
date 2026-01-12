// Package geoblocking 地域封禁模块
package geoblocking

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Fetcher GeoIP 数据获取器
// 负责从外部 URL 获取 GeoIP CSV 数据
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
}

// NewFetcher 创建新的 GeoIP 数据获取器
// timeout: HTTP 请求超时时间
func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// Fetch 从指定 URL 获取 GeoIP CSV 数据
// 返回原始字节数据
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

// FetchWithRetry 带重试的获取数据（当前实现不重试，直接返回）
// 根据需求，失败后等待下一周期，不进行重试
// maxRetries: 最大重试次数（当前未使用）
func (f *Fetcher) FetchWithRetry(url string, maxRetries int) ([]byte, error) {
	return f.Fetch(url)
}
