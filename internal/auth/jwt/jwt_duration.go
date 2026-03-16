package jwt

import "time"

// GetTokenDuration 获取 token 有效期
func (s *JWTService) GetTokenDuration() time.Duration {
	return s.tokenDuration
}
