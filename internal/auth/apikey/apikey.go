package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

const (
	// KeyPrefix API Key 前缀
	KeyPrefix = "sk_live_"
	// KeyLength API Key 长度（不含前缀）
	KeyLength = 32
)

// GenerateKey 生成 API Key
func GenerateKey() (string, string, error) {
	// 生成随机字节
	bytes := make([]byte, KeyLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// 转换为十六进制字符串
	randomStr := hex.EncodeToString(bytes)

	// 添加前缀
	key := KeyPrefix + randomStr

	// 计算 Hash
	hash := HashKey(key)

	return key, hash, nil
}

// HashKey 计算 API Key 的 SHA256 Hash
func HashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// GenerateKeyPrefix 生成用于显示的 Key 前缀
func GenerateKeyPrefix() string {
	return KeyPrefix + uuid.New().String()[:8]
}
