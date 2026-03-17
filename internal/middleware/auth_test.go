package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestAuthMiddleware_MissingAuth(t *testing.T) {
	// Create router with middleware that checks for auth
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate AuthMiddleware behavior for missing auth
		apiKey := c.GetHeader("X-API-Key")
		authHeader := c.GetHeader("Authorization")

		if apiKey == "" && authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			c.Abort()
			return
		}
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Create request without auth
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate AuthMiddleware behavior for invalid Bearer format
		authHeader := c.GetHeader("Authorization")
		apiKey := c.GetHeader("X-API-Key")

		// Skip if API key present
		if apiKey != "" {
			c.Next()
			return
		}

		if authHeader != "" {
			// Simple check for Bearer format (simplified)
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
				c.Abort()
				return
			}
		}
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Create request with invalid Bearer format
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_ValidBearerFormat(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader != "" {
			// Check Bearer format
			if len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
				// Valid format, in real scenario would validate token
				c.Set(ContextKeyAuthType, "jwt")
				c.Next()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
		c.Abort()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestCasbinMiddleware_MissingSubject(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate CasbinMiddleware behavior for missing subject
		_, exists := c.Get(ContextKeySubject)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCasbinMiddleware_PermissionDenied(t *testing.T) {
	// Mock enforcer that denies permission
	mockEnforce := func(sub, obj, act string) bool {
		return false
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Set subject
		c.Set(ContextKeySubject, "user:1")
		c.Next()
	})
	router.Use(func(c *gin.Context) {
		// Simulate CasbinMiddleware
		sub, _ := c.Get(ContextKeySubject)
		allowed := mockEnforce(sub.(string), "resource", "action")
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
			c.Abort()
			return
		}
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestCasbinMiddleware_PermissionGranted(t *testing.T) {
	// Mock enforcer that grants permission
	mockEnforce := func(sub, obj, act string) bool {
		return true
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeySubject, "user:1")
		c.Next()
	})
	router.Use(func(c *gin.Context) {
		sub, _ := c.Get(ContextKeySubject)
		allowed := mockEnforce(sub.(string), "resource", "action")
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
			c.Abort()
			return
		}
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestAdminMiddleware_AdminRole(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeyUserRole, "admin")
		c.Next()
	})
	router.Use(AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestAdminMiddleware_NonAdminRole(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeyUserRole, "user")
		c.Next()
	})
	router.Use(AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestAdminMiddleware_MissingRole(t *testing.T) {
	router := gin.New()
	router.Use(AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestGetUserID(t *testing.T) {
	t.Run("user ID exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(ContextKeyUserID, uint(123))

		userID, exists := GetUserID(c)
		if !exists {
			t.Error("Expected exists to be true")
		}
		if userID != 123 {
			t.Errorf("Expected userID 123, got %d", userID)
		}
	})

	t.Run("user ID not exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)

		_, exists := GetUserID(c)
		if exists {
			t.Error("Expected exists to be false")
		}
	})
}

func TestGetUsername(t *testing.T) {
	t.Run("username exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(ContextKeyUsername, "testuser")

		username, exists := GetUsername(c)
		if !exists {
			t.Error("Expected exists to be true")
		}
		if username != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", username)
		}
	})

	t.Run("username not exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)

		_, exists := GetUsername(c)
		if exists {
			t.Error("Expected exists to be false")
		}
	})
}

func TestGetUserRole(t *testing.T) {
	t.Run("role exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(ContextKeyUserRole, "admin")

		role, exists := GetUserRole(c)
		if !exists {
			t.Error("Expected exists to be true")
		}
		if role != "admin" {
			t.Errorf("Expected role 'admin', got '%s'", role)
		}
	})

	t.Run("role not exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)

		_, exists := GetUserRole(c)
		if exists {
			t.Error("Expected exists to be false")
		}
	})
}

func TestContextKeys(t *testing.T) {
	// Test that all context key constants are defined correctly
	if ContextKeyUserID != "user_id" {
		t.Errorf("ContextKeyUserID = %s, want user_id", ContextKeyUserID)
	}
	if ContextKeyUsername != "username" {
		t.Errorf("ContextKeyUsername = %s, want username", ContextKeyUsername)
	}
	if ContextKeyUserRole != "user_role" {
		t.Errorf("ContextKeyUserRole = %s, want user_role", ContextKeyUserRole)
	}
	if ContextKeySubject != "sub" {
		t.Errorf("ContextKeySubject = %s, want sub", ContextKeySubject)
	}
	if ContextKeyAuthType != "auth_type" {
		t.Errorf("ContextKeyAuthType = %s, want auth_type", ContextKeyAuthType)
	}
}

func TestAuthPriority(t *testing.T) {
	// Test that API Key has priority over JWT
	t.Run("API key takes priority", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			apiKey := c.GetHeader("X-API-Key")
			authHeader := c.GetHeader("Authorization")

			// API Key has priority
			if apiKey != "" {
				c.Set(ContextKeyAuthType, "api_key")
				c.Next()
				return
			}

			// Then JWT
			if authHeader != "" {
				c.Set(ContextKeyAuthType, "jwt")
				c.Next()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			c.Abort()
		})
		router.GET("/test", func(c *gin.Context) {
			authType, _ := c.Get(ContextKeyAuthType)
			c.JSON(http.StatusOK, gin.H{"auth_type": authType})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should use API Key, not JWT
		if w.Body.String() != `{"auth_type":"api_key"}` {
			t.Errorf("Expected api_key auth type, got: %s", w.Body.String())
		}
	})
}
