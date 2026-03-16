package handles

import (
	"encoding/json"
	"net/http"
	"strconv"

	"rho-aias/internal/middleware"
	"rho-aias/internal/models"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// UserHandle 用户管理处理器
type UserHandle struct {
	userService  *services.UserService
	auditService *services.AuditService
	enforcer     interface {
		AssignRoleToUser(userID uint, role string) error
	}
}

// NewUserHandle 创建用户管理处理器
func NewUserHandle(
	userService *services.UserService,
	auditService *services.AuditService,
	enforcer interface {
		AssignRoleToUser(userID uint, role string) error
	},
) *UserHandle {
	return &UserHandle{
		userService:  userService,
		auditService: auditService,
		enforcer:     enforcer,
	}
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=6"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Role     string `json:"role" binding:"required,oneof=admin user"`
}

// CreateUser 创建用户
// @Summary 创建用户
// @Description 创建新用户
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateUserRequest true "创建用户请求"
// @Success 201 {object} models.User
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users [post]
func (h *UserHandle) CreateUser(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	username, _ := middleware.GetUsername(c)

	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.CreateUser(req.Username, req.Password, req.Nickname, req.Email, req.Role)
	if err != nil {
		if err == services.ErrUserAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 分配角色
	if err := h.enforcer.AssignRoleToUser(user.ID, req.Role); err != nil {
		// 记录错误但不影响用户创建
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign role"})
		return
	}

	// 记录审计日志
	detail, _ := json.Marshal(map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})
	_ = h.auditService.Log(services.LogRequest{
		UserID:     userID,
		Username:   username,
		Action:     models.ActionCreateUser,
		Resource:   models.ResourceUser,
		ResourceID: strconv.FormatUint(uint64(user.ID), 10),
		Detail:     string(detail),
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	c.JSON(http.StatusCreated, user)
}

// ListUsers 列出用户
// @Summary 列出用户
// @Description 获取用户列表
// @Tags 用户管理
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/users [get]
func (h *UserHandle) ListUsers(c *gin.Context) {
	users, err := h.userService.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Role     string `json:"role" binding:"omitempty,oneof=admin user"`
	Active   *bool  `json:"active"`
}

// UpdateUser 更新用户
// @Summary 更新用户
// @Description 更新用户信息
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "用户ID"
// @Param request body UpdateUserRequest true "更新用户请求"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id} [put]
func (h *UserHandle) UpdateUser(c *gin.Context) {
	currentUserID, _ := middleware.GetUserID(c)
	currentUsername, _ := middleware.GetUsername(c)

	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})
	if req.Nickname != "" {
		updates["nickname"] = req.Nickname
	}
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Role != "" {
		updates["role"] = req.Role
		// 更新 Casbin 角色
		if err := h.enforcer.AssignRoleToUser(uint(userID), req.Role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
			return
		}
	}
	if req.Active != nil {
		updates["active"] = *req.Active
	}

	if err := h.userService.UpdateUser(uint(userID), updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 记录审计日志
	detail, _ := json.Marshal(updates)
	_ = h.auditService.Log(services.LogRequest{
		UserID:     currentUserID,
		Username:   currentUsername,
		Action:     models.ActionUpdateUser,
		Resource:   models.ResourceUser,
		ResourceID: userIDStr,
		Detail:     string(detail),
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	c.JSON(http.StatusOK, gin.H{"message": "user updated successfully"})
}

// DeleteUser 删除用户
// @Summary 删除用户
// @Description 删除用户（软删除）
// @Tags 用户管理
// @Produce json
// @Security BearerAuth
// @Param id path int true "用户ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id} [delete]
func (h *UserHandle) DeleteUser(c *gin.Context) {
	currentUserID, _ := middleware.GetUserID(c)
	currentUsername, _ := middleware.GetUsername(c)

	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	// 不能删除自己
	if uint(userID) == currentUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete yourself"})
		return
	}

	if err := h.userService.DeleteUser(uint(userID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 记录审计日志
	_ = h.auditService.Log(services.LogRequest{
		UserID:     currentUserID,
		Username:   currentUsername,
		Action:     models.ActionDeleteUser,
		Resource:   models.ResourceUser,
		ResourceID: userIDStr,
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

// GetUser 获取单个用户信息
// @Summary 获取用户信息
// @Description 根据ID获取用户详细信息
// @Tags 用户管理
// @Produce json
// @Security BearerAuth
// @Param id path int true "用户ID"
// @Success 200 {object} models.User
// @Failure 401 {object} map[string]string
// @Router /api/users/{id} [get]
func (h *UserHandle) GetUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	user, err := h.userService.GetUserByID(uint(userID))
	if err != nil {
		if err == services.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}
