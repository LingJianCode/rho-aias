package bootstrap

import (
	"os"
	"time"

	"rho-aias/internal/auth/captcha"
	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/casbin"
	"rho-aias/internal/config"
	"rho-aias/internal/database"
	"rho-aias/internal/handles"
	"rho-aias/internal/logger"
	"rho-aias/internal/services"
)

// AuthDeps 认证系统初始化结果
type AuthDeps struct {
	JWTService    *jwt.JWTService
	AuthService   *services.AuthService
	UserService   *services.UserService
	APIKeyService *services.APIKeyService
	AuditService  *services.AuditService
	CaptchaStore  *captcha.MemoryStore
	Enforcer      *casbin.Enforcer
	AuthHandle    *handles.AuthHandle
	APIKeyHandle  *handles.APIKeyHandle
	UserHandle    *handles.UserHandle
	AuditHandle   *handles.AuditHandle
}

// InitAuth 初始化 Casbin / JWT / Captcha / Service / Handle 全链路
func InitAuth(cfg *config.Config, authDB *database.Database) *AuthDeps {

	enforcer, err := casbin.NewEnforcer(authDB.DB)
	if err != nil {
		logger.Fatalf("[Auth] Failed to initialize casbin: %v", err)
	}

	if err := enforcer.InitDefaultPolicies(); err != nil {
		logger.Warnf("[Auth] Failed to initialize default policies: %v", err)
	}

	if err := authDB.InitDefaultUser(enforcer); err != nil {
		logger.Warnf("[Auth] Failed to initialize default user: %v", err)
	}

	jwtSecret := cfg.Auth.JWTSecret
	if jwtSecret == "" {
		jwtSecret = os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default-secret-change-me"
			logger.Warn("[Auth] Using default JWT secret, please set in config or env")
		}
	}

	jwtSvc := jwt.NewJWTService(
		jwtSecret,
		time.Duration(cfg.Auth.TokenDuration)*time.Minute,
		cfg.Auth.JWTIssuer,
	)

	authSvc := services.NewAuthService(authDB.DB, jwtSvc)
	userSvc := services.NewUserService(authDB.DB)
	apiKeySvc := services.NewAPIKeyService(authDB.DB, enforcer)
	auditSvc := services.NewAuditService(authDB.DB)

	captchaStore, err := captcha.NewMemoryStore()
	if err != nil {
		logger.Fatalf("Failed to initialize captcha store: %v", err)
	}
	captchaSvc := captcha.NewCaptchaService(
		captchaStore,
		time.Duration(cfg.Auth.CaptchaDuration)*time.Minute,
	)

	authHandle := handles.NewAuthHandle(authSvc, userSvc, captchaSvc)
	apiKeyHandle := handles.NewAPIKeyHandle(apiKeySvc, auditSvc)
	userHandle := handles.NewUserHandle(userSvc, auditSvc, enforcer)
	auditHandle := handles.NewAuditHandle(auditSvc)

	logger.Info("[Main] Authentication module initialized")

	return &AuthDeps{
		JWTService:   jwtSvc,
		AuthService:  authSvc,
		UserService:  userSvc,
		APIKeyService: apiKeySvc,
		AuditService: auditSvc,
		CaptchaStore: captchaStore,
		Enforcer:     enforcer,
		AuthHandle:   authHandle,
		APIKeyHandle: apiKeyHandle,
		UserHandle:   userHandle,
		AuditHandle:  auditHandle,
	}
}
