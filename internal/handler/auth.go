package handler

import (
	"net/http"

	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// AuthHandler は認証ハンドラー
type AuthHandler struct {
	authService *service.AuthenticationService
}

// NewAuthHandler は新しい認証ハンドラーを作成
func NewAuthHandler(authService *service.AuthenticationService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Login はログイン処理
func (h *AuthHandler) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, response)
}
