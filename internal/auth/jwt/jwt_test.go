package jwt

import (
	"testing"
	"time"
)

func TestNewJWTService(t *testing.T) {
	tests := []struct {
		name          string
		secretKey     string
		tokenDuration time.Duration
		issuer        string
	}{
		{
			name:          "valid config",
			secretKey:     "test-secret-key-32-characters",
			tokenDuration: time.Hour,
			issuer:        "test-issuer",
		},
		{
			name:          "empty secret key",
			secretKey:     "",
			tokenDuration: time.Hour,
			issuer:        "test-issuer",
		},
		{
			name:          "empty issuer",
			secretKey:     "test-secret-key",
			tokenDuration: time.Hour,
			issuer:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewJWTService(tt.secretKey, tt.tokenDuration, tt.issuer)
			if service == nil {
				t.Error("NewJWTService() returned nil")
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	service := NewJWTService("test-secret-key-32-characters", time.Hour, "test-issuer")

	tests := []struct {
		name     string
		userID   uint
		username string
		role     string
		wantErr  bool
	}{
		{
			name:     "valid token generation",
			userID:   1,
			username: "testuser",
			role:     "admin",
			wantErr:  false,
		},
		{
			name:     "empty username",
			userID:   1,
			username: "",
			role:     "user",
			wantErr:  false, // GenerateToken doesn't validate username
		},
		{
			name:     "zero user ID",
			userID:   0,
			username: "testuser",
			role:     "user",
			wantErr:  false, // GenerateToken doesn't validate userID
		},
		{
			name:     "empty role",
			userID:   1,
			username: "testuser",
			role:     "",
			wantErr:  false, // GenerateToken doesn't validate role
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := service.GenerateToken(tt.userID, tt.username, tt.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token == "" {
				t.Error("GenerateToken() returned empty token")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	service := NewJWTService("test-secret-key-32-characters", time.Hour, "test-issuer")

	// Generate a valid token for testing
	validToken, _ := service.GenerateToken(1, "testuser", "admin")

	// Create a service with different secret to test invalid signature
	differentService := NewJWTService("different-secret-key-32-chars", time.Hour, "test-issuer")

	tests := []struct {
		name      string
		token     string
		wantErr   error
		wantValid bool
	}{
		{
			name:      "valid token",
			token:     validToken,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "invalid token format",
			token:     "invalid-token",
			wantErr:   ErrInvalidToken,
			wantValid: false,
		},
		{
			name:      "empty token",
			token:     "",
			wantErr:   ErrInvalidToken,
			wantValid: false,
		},
		{
			name:      "wrong signature",
			token:     validToken, // Token signed by different key
			wantErr:   nil,        // Will be validated by differentService
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For wrong signature test, use differentService
			svc := service
			if tt.name == "wrong signature" {
				svc = differentService
			}

			claims, err := svc.ValidateToken(tt.token)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if !tt.wantValid {
				if err == nil {
					t.Error("ValidateToken() expected error for invalid token")
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateToken() unexpected error = %v", err)
				return
			}

			if claims == nil {
				t.Error("ValidateToken() returned nil claims for valid token")
				return
			}

			if claims.Username != "testuser" {
				t.Errorf("ValidateToken() username = %v, want %v", claims.Username, "testuser")
			}
			if claims.Role != "admin" {
				t.Errorf("ValidateToken() role = %v, want %v", claims.Role, "admin")
			}
			if claims.UserID != 1 {
				t.Errorf("ValidateToken() userID = %v, want %v", claims.UserID, 1)
			}
		})
	}
}

func TestValidateToken_Expired(t *testing.T) {
	// Create a service with very short duration
	service := NewJWTService("test-secret-key-32-characters", time.Millisecond, "test-issuer")

	token, _ := service.GenerateToken(1, "testuser", "admin")

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err := service.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrExpiredToken)
	}
}

func TestRefreshToken(t *testing.T) {
	service := NewJWTService("test-secret-key-32-characters", time.Hour, "test-issuer")

	// Generate a valid token
	validToken, _ := service.GenerateToken(1, "testuser", "admin")

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "refresh valid token",
			token:   validToken,
			wantErr: false,
		},
		{
			name:    "refresh invalid token",
			token:   "invalid-token",
			wantErr: true,
		},
		{
			name:    "refresh empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, err := service.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if newToken == "" {
					t.Error("RefreshToken() returned empty token")
				}
				if newToken == tt.token {
					t.Error("RefreshToken() returned same token")
				}

				// Verify the new token is valid
				claims, err := service.ValidateToken(newToken)
				if err != nil {
					t.Errorf("RefreshToken() new token invalid: %v", err)
				}
				if claims.Username != "testuser" {
					t.Errorf("RefreshToken() username mismatch: got %v, want testuser", claims.Username)
				}
			}
		})
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	// Create a service with very short duration
	service := NewJWTService("test-secret-key-32-characters", time.Millisecond, "test-issuer")

	token, _ := service.GenerateToken(1, "testuser", "admin")

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err := service.RefreshToken(token)
	if err != ErrExpiredToken {
		t.Errorf("RefreshToken() error = %v, want %v", err, ErrExpiredToken)
	}
}

func TestClaims(t *testing.T) {
	service := NewJWTService("test-secret-key-32-characters", time.Hour, "test-issuer")

	token, _ := service.GenerateToken(123, "testuser", "admin")

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != 123 {
		t.Errorf("Claims.UserID = %v, want %v", claims.UserID, 123)
	}
	if claims.Username != "testuser" {
		t.Errorf("Claims.Username = %v, want %v", claims.Username, "testuser")
	}
	if claims.Role != "admin" {
		t.Errorf("Claims.Role = %v, want %v", claims.Role, "admin")
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Claims.Issuer = %v, want %v", claims.Issuer, "test-issuer")
	}
}

func TestMultipleServices(t *testing.T) {
	service1 := NewJWTService("secret-key-1-32-characters-long", time.Hour, "issuer1")
	service2 := NewJWTService("secret-key-2-32-characters-long", time.Hour, "issuer2")

	token1, _ := service1.GenerateToken(1, "user1", "admin")
	token2, _ := service2.GenerateToken(2, "user2", "user")

	// Each service should validate its own tokens
	claims1, err := service1.ValidateToken(token1)
	if err != nil {
		t.Errorf("Service1 failed to validate its own token: %v", err)
	}
	if claims1.Username != "user1" {
		t.Errorf("Service1 claims username = %v, want user1", claims1.Username)
	}

	claims2, err := service2.ValidateToken(token2)
	if err != nil {
		t.Errorf("Service2 failed to validate its own token: %v", err)
	}
	if claims2.Username != "user2" {
		t.Errorf("Service2 claims username = %v, want user2", claims2.Username)
	}

	// Services should not validate each other's tokens
	_, err = service1.ValidateToken(token2)
	if err == nil {
		t.Error("Service1 should not validate Service2's token")
	}

	_, err = service2.ValidateToken(token1)
	if err == nil {
		t.Error("Service2 should not validate Service1's token")
	}
}
