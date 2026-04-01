package captcha

import (
	"fmt"
	"image/color"
	"strings"
	"sync"
	"time"

	"github.com/mojocn/base64Captcha"
	"github.com/robfig/cron/v3"
)

// CaptchaStore 验证码存储接口
type CaptchaStore interface {
	Set(id string, value string, ttl time.Duration) error
	Get(id string) (string, bool)
	Delete(id string)
}

// MemoryStore 内存存储实现
type MemoryStore struct {
	data map[string]*captchaItem
	mu   sync.RWMutex
	cron *cron.Cron
}

type captchaItem struct {
	value     string
	expiresAt time.Time
}

// NewMemoryStore 创建内存存储
func NewMemoryStore() (*MemoryStore, error) {
	store := &MemoryStore{
		data: make(map[string]*captchaItem),
	}

	// 初始化 Cron 定时任务
	store.cron = cron.New(cron.WithSeconds())

	// 添加定时清理任务（每 1 分钟）
	if _, err := store.cron.AddFunc("@every 1m", func() {
		store.cleanup()
	}); err != nil {
		return nil, fmt.Errorf("failed to add cleanup cron job: %w", err)
	}

	// 启动定时任务
	store.cron.Start()

	return store, nil
}

// Set 设置验证码
func (s *MemoryStore) Set(id string, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = &captchaItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// Get 获取验证码
func (s *MemoryStore) Get(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, exists := s.data[id]
	if !exists || time.Now().After(item.expiresAt) {
		return "", false
	}
	return item.value, true
}

// Delete 删除验证码
func (s *MemoryStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
}

// cleanup 定期清理过期验证码
func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, item := range s.data {
		if now.After(item.expiresAt) {
			delete(s.data, id)
		}
	}
}

// CaptchaService 验证码服务
type CaptchaService struct {
	store  CaptchaStore
	driver *base64Captcha.DriverString
	ttl    time.Duration
}

// NewCaptchaService 创建验证码服务
func NewCaptchaService(store CaptchaStore, ttl time.Duration) *CaptchaService {
	driver := &base64Captcha.DriverString{
		Height:          60,
		Width:           240,
		NoiseCount:      5,
		ShowLineOptions: base64Captcha.OptionShowSlimeLine | base64Captcha.OptionShowHollowLine,
		Length:          4,
		Source:          "1234567890qwertyuioplkjhgfdsazxcvbnm",
		BgColor:         &color.RGBA{R: 240, G: 240, B: 246, A: 255},
		Fonts:           []string{"wqy-microhei.ttc"},
	}

	return &CaptchaService{
		store:  store,
		driver: driver,
		ttl:    ttl,
	}
}

// Generate 生成验证码
// 返回: captchaID, base64图片, 错误
func (s *CaptchaService) Generate() (string, string, error) {
	// 生成验证码内容
	id, content, answer := s.driver.GenerateIdQuestionAnswer()

	// 存储答案
	if err := s.store.Set(id, answer, s.ttl); err != nil {
		return "", "", err
	}

	// 生成图片
	item, err := s.driver.DrawCaptcha(content)
	if err != nil {
		return "", "", err
	}

	// 转换为 base64 (EncodeB64string 已经包含 data:image/png;base64, 前缀)
	base64Img := item.EncodeB64string()

	return id, base64Img, nil
}

// Verify 验证验证码
func (s *CaptchaService) Verify(id, answer string) bool {
	storedAnswer, exists := s.store.Get(id)
	if !exists {
		return false
	}

	// 验证后删除
	defer s.store.Delete(id)

	// 不区分大小写
	return strings.EqualFold(storedAnswer, answer)
}

// VerifyCaseSensitive 区分大小写验证
func (s *CaptchaService) VerifyCaseSensitive(id, answer string) bool {
	storedAnswer, exists := s.store.Get(id)
	if !exists {
		return false
	}

	defer s.store.Delete(id)
	return storedAnswer == answer
}
