package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Ebpf   EbpfConfig   `yaml:"ebpf"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type EbpfConfig struct {
	InterfaceName string `yaml:"interface_name"`
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
