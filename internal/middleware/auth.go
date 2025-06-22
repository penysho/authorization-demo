package middleware

import (
	"net/http"
	"strings"

	"authorization-demo/internal/auth"
	"authorization-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware はJWT認証ミドルウェア
func AuthMiddleware(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Bearer トークンの形式をチェック
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		// トークンを検証
		user, err := authService.ValidateToken(tokenParts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// ユーザー情報をコンテキストに設定
		c.Set("user", user)
		c.Next()
	}
}

// GetUserFromContext はコンテキストからユーザー情報を取得
func GetUserFromContext(c *gin.Context) (*model.User, bool) {
	user, exists := c.Get("user")
	if !exists {
		return nil, false
	}

	userModel, ok := user.(*model.User)
	return userModel, ok
}
