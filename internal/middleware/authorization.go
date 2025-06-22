package middleware

import (
	"net/http"

	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// resolveResource はリクエストパラメータに基づいてリソース名を解決
func resolveResource(c *gin.Context, resource string) string {
	// 商品IDが含まれるパスの場合、商品固有のリソース名を生成
	if productID := c.Param("id"); productID != "" && resource == "products" {
		return "product_" + productID
	}
	return resource
}

// EnhancedRequirePermission は強化された認可サービス用のミドルウェアを返す
func EnhancedRequirePermission(authzService *service.EnhancedAuthorizationService, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// コンテキストからユーザー情報を取得
		user, exists := GetUserFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
			c.Abort()
			return
		}

		// リソース名を動的に解決（例：商品IDが含まれる場合）
		resolvedResource := resolveResource(c, resource)

		// 権限チェック
		allowed, err := authzService.CheckPermission(user, resolvedResource, action)
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
