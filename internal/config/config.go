package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Ebpf   EbpfConfig   `yaml:"ebpf"`
	Intel  IntelConfig  `yaml:"intel"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type EbpfConfig struct {
	InterfaceName string `yaml:"interface_name"`
}

// IntelConfig 情报配置
type IntelConfig struct {
	Enabled        bool                   `yaml:"enabled"`         // 总开关
	PersistenceDir string                 `yaml:"persistence_dir"` // 持久化目录
	Sources        map[string]IntelSource `yaml:"sources"`         // 情报源配置 (map 结构支持动态添加)
	BatchSize      int                    `yaml:"batch_size"`      // 批量更新大小
}

// IntelSource 单个情报源配置
type IntelSource struct {
	Enabled  bool   `yaml:"enabled"` // 是否启用
	Schedule string `yaml:"schedule"` // Cron 表达式 (如: "0 * * * *" 表示每小时整点)
	URL      string `yaml:"url"`     // 数据源 URL
	Format   string `yaml:"format"`  // 格式类型 (ipsum/spamhaus)
}

func NewConfig(fileName string) *Config {
	// 打开 YAML 文件
	file, err := os.Open(fileName)
	if err != nil {
		panic(fmt.Sprintf("Error opening file:%e", err))
	}
	defer file.Close()

	// 创建解析器
	decoder := yaml.NewDecoder(file)

	// 配置对象
	var config Config

	// 解析 YAML 数据
	err = decoder.Decode(&config)
	if err != nil {
		panic(fmt.Sprintf("Error decoding YAML:%e", err))
	}
	return &config
}
