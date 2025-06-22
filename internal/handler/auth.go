package handler

import (
	"net/http"

	"authorization-demo/internal/auth"
	"authorization-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// AuthHandler は認証ハンドラー
type AuthHandler struct {
	authService *auth.Service
}

// NewAuthHandler は新しい認証ハンドラーを作成
func NewAuthHandler(authService *auth.Service) *AuthHandler {
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
		if err == auth.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, response)
}
