package middleware

import (
	"net/http"

	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// RequirePermission は認可サービス用のミドルウェアを返す
func RequirePermission(authzService *service.AuthorizationService, resourceType, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// コンテキストからユーザー情報を取得
		user, exists := GetUserFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
			c.Abort()
			return
		}

		var resourceID *string
		if c.Param("id") != "" {
			id := c.Param("id")
			resourceID = &id
		}

		// 権限チェック
		allowed, err := authzService.CheckPermission(user, resourceType, action, resourceID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}
