package blocklog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// JsonLogReader JSONL 日志文件查询器
type JsonLogReader struct {
	logDir string // 日志目录
}

// NewJsonLogReader 创建 JSONL 日志查询器
func NewJsonLogReader(logDir string) *JsonLogReader {
	return &JsonLogReader{logDir: logDir}
}

// hourFormatRegex 验证 hour 参数格式: 2026-04-17_14
var hourFormatRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}_\d{2}$`)

// PageResult 分页查询结果
type PageResult struct {
	Records  []BlockRecord `json:"records"`
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// QueryPage 从单个小时的 JSONL 文件中分页查询记录
// hour 格式: "2026-04-17_14"，直接映射为文件名 2026-04-17_14.jsonl
// 返回匹配过滤条件的分页结果，使用流式扫描不加载整个文件到内存
func (r *JsonLogReader) QueryPage(hour string, filter RecordFilter) (*PageResult, error) {
	// 验证 hour 格式
	if !hourFormatRegex.MatchString(hour) {
		return nil, fmt.Errorf("invalid hour format, expected YYYY-MM-DD_HH, got: %s", hour)
	}

	// 构造文件路径
	filename := hour + ".jsonl"
	filePath := filepath.Join(r.logDir, filename)

	// 安全检查：防止路径遍历
	if strings.Contains(hour, "..") {
		return nil, fmt.Errorf("invalid hour parameter")
	}

	// 打开文件
	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，返回空结果
			return &PageResult{
				Records:  []BlockRecord{},
				Total:    0,
				Page:     filter.Page,
				PageSize: filter.PageSize,
			}, nil
		}
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	// 设置默认分页参数
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}

	// 流式扫描：收集所有匹配行，记录行号用于分页
	// 先收集所有匹配记录的偏移和内容，然后按分页截取
	var matched []BlockRecord
	scanner := bufio.NewScanner(f)
	// 增大缓冲区以支持较长的行
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record BlockRecord
		if err := json.Unmarshal(line, &record); err != nil {
			continue // 跳过无法解析的行
		}

		// 应用过滤条件
		if !matchFilter(record, filter) {
			continue
		}

		matched = append(matched, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log file: %w", err)
	}

	// 计算分页（最新记录在前，即从后往前）
	total := len(matched)
	offset := (page - 1) * pageSize

	// 从后往前取（最新的记录在文件末尾）
	start := total - offset - pageSize
	end := total - offset
	if start < 0 {
		start = 0
	}
	if end > total {
		end = total
	}
	if start >= end {
		return &PageResult{
			Records:  []BlockRecord{},
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		}, nil
	}

	// 反转切片使得最新记录在前
	pageRecords := make([]BlockRecord, 0, end-start)
	for i := end - 1; i >= start; i-- {
		pageRecords = append(pageRecords, matched[i])
	}

	return &PageResult{
		Records:  pageRecords,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// AggregateTopIPs 从指定小时的 JSONL 文件中聚合 IP 计数，仅返回阻断次数 > 1 的 IP
// hour 格式: "2026-04-17T14"（自动转为文件名格式 2026-04-17_14.jsonl）
func (r *JsonLogReader) AggregateTopIPs(hour string) []IPCount {
	// 构造文件路径：将 "2026-04-17T14" 格式转为 "2026-04-17_14"
	fileHour := strings.ReplaceAll(hour, "T", "_")

	// 验证转换后的 hour 格式
	if !hourFormatRegex.MatchString(fileHour) {
		return nil
	}

	filename := fileHour + ".jsonl"
	filePath := filepath.Join(r.logDir, filename)

	// 安全检查：防止路径遍历
	if strings.Contains(fileHour, "..") {
		return nil
	}

	// 打开文件
	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	defer f.Close()

	// 逐行扫描聚合 IP 计数
	ipCounts := make(map[string]int)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record BlockRecord
		if err := json.Unmarshal(line, &record); err != nil {
			continue
		}

		if record.SrcIP != "" {
			ipCounts[record.SrcIP]++
		}
	}

	if len(ipCounts) == 0 {
		return nil
	}

	// 仅保留阻断次数 > 1 的 IP（过滤单次噪声）
	result := make([]IPCount, 0)
	for ip, count := range ipCounts {
		if count > 1 {
			result = append(result, IPCount{IP: ip, Count: count})
		}
	}

	return result
}

// matchFilter 检查记录是否匹配过滤条件
func matchFilter(record BlockRecord, filter RecordFilter) bool {
	if filter.MatchType != "" && record.MatchType != filter.MatchType {
		return false
	}
	if filter.RuleSource != "" && record.RuleSource != filter.RuleSource {
		return false
	}
	if filter.SrcIP != "" && record.SrcIP != filter.SrcIP {
		return false
	}
	if filter.CountryCode != "" && record.CountryCode != filter.CountryCode {
		return false
	}
	return true
}
