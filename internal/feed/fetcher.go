// Package feed 为威胁情报、地域封禁等数据馈送（Data Feed）模块提供公共基础设施，
// 包括泛型持久化缓存（Cache）、HTTP 数据获取器（Fetcher）、
// 并发互斥锁池（MutexPool）、数据源状态（SourceStatus）和数据库状态记录辅助函数。
//
// 各模块通过泛型参数 [T] 传入自己的数据类型，实现类型安全的复用。
package feed

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
