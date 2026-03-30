// Package response provides unified JSON response structures and helpers for API handlers.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// R is the standard API response structure.
type R struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Business error code constants
const (
	CodeOK = 0

	// Parameter errors 40001-40099
	CodeInvalidParam   = 40001
	CodeInvalidRequest = 40002
	CodeInvalidCaptcha = 40003

	// Authentication errors 40101-40199
	CodeUnauthorized    = 40101
	CodeTokenExpired    = 40102
	CodeInvalidPassword = 40103
	CodeUserInactive    = 40104
	CodeInvalidAPIKey   = 40105
	CodeAPIKeyExpired   = 40106

	// Permission errors 40301-40399
	CodePermissionDenied = 40301
	CodeAdminRequired    = 40302

	// Resource not found 40401-40499
	CodeUserNotFound   = 40401
	CodeLogNotFound    = 40402
	CodeRecordNotFound = 40403
	CodeSourceNotFound = 40404

	// Conflict errors 40901-40999
	CodeUserExists         = 40901
	CodeWhitelistConflict  = 40902
	CodeUsernameExists     = 40903
	CodeRuleConflict       = 40904

	// Server errors 50001-50099
	CodeInternal = 50001
	CodeDBError  = 50002
)

// OK returns a successful response with data
func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, R{Code: CodeOK, Message: "ok", Data: data})
}

// OKMsg returns a successful response with only a message
func OKMsg(c *gin.Context, msg string) {
	c.JSON(http.StatusOK, R{Code: CodeOK, Message: msg})
}

// Created returns a 201 Created response with data
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, R{Code: CodeOK, Message: "created", Data: data})
}

// Fail returns an error response with custom HTTP status and business code
func Fail(c *gin.Context, httpStatus int, code int, message string) {
	c.JSON(httpStatus, R{Code: code, Message: message})
}

// BadRequest returns a 400 Bad Request error
func BadRequest(c *gin.Context, message string) {
	Fail(c, http.StatusBadRequest, CodeInvalidParam, message)
}

// Unauthorized returns a 401 Unauthorized error
func Unauthorized(c *gin.Context, message string) {
	Fail(c, http.StatusUnauthorized, CodeUnauthorized, message)
}

// Forbidden returns a 403 Forbidden error
func Forbidden(c *gin.Context, message string) {
	Fail(c, http.StatusForbidden, CodePermissionDenied, message)
}

// NotFound returns a 404 Not Found error
func NotFound(c *gin.Context, message string) {
	Fail(c, http.StatusNotFound, CodeRecordNotFound, message)
}

// InternalError returns a 500 Internal Server Error
func InternalError(c *gin.Context, message string) {
	Fail(c, http.StatusInternalServerError, CodeInternal, message)
}

// Conflict returns a 409 Conflict error
func Conflict(c *gin.Context, code int, message string) {
	Fail(c, http.StatusConflict, code, message)
}
