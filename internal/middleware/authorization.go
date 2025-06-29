package middleware

import (
	"net/http"
	"strings"

	"authorization-demo/internal/model"
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

// RequirePermission は認可サービス用のミドルウェアを返す
func RequirePermission(authzService *service.AuthorizationService, resource, action string) gin.HandlerFunc {
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
		allowed, err := authzService.CheckPermission(user, resolvedResource, action, nil)
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

// RequireProductAccess は商品固有のABACベースアクセス制御ミドルウェア
func RequireProductAccess(authzService *service.AuthorizationService, productService service.ProductService, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// コンテキストからユーザー情報を取得
		user, exists := GetUserFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
			c.Abort()
			return
		}

		// 商品IDを取得
		productID := c.Param("id")
		if productID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
			c.Abort()
			return
		}

		// 商品情報を取得
		product, err := productService.GetProduct(c.Request.Context(), productID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get product"})
			}
			c.Abort()
			return
		}

		// 商品アクセス権限をチェック
		allowed, err := authzService.CheckPermission(user, "products", action, &productID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization check failed",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"reason":  "You do not have permission to access this product",
				"product": productID,
				"action":  action,
			})
			c.Abort()
			return
		}

		// 商品情報をコンテキストに保存（後続のハンドラーで使用可能）
		c.Set("product", product)
		c.Next()
	}
}

// RequireBulkProductAccess は複数商品へのアクセス制御ミドルウェア（商品一覧など）
func RequireBulkProductAccess(authzService *service.AuthorizationService, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// コンテキストからユーザー情報を取得
		user, exists := GetUserFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
			c.Abort()
			return
		}

		// 基本的なRBAC権限チェック（商品リソースへのアクセス権限）
		allowed, err := authzService.CheckPermission(user, "products", action, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to products"})
			c.Abort()
			return
		}

		// ユーザー情報をコンテキストに保存（後続でフィルタリングに使用）
		c.Set("user", user)
		c.Next()
	}
}

// GetProductFromContext はコンテキストから商品情報を取得
func GetProductFromContext(c *gin.Context) (*model.Product, bool) {
	if product, exists := c.Get("product"); exists {
		if p, ok := product.(*model.Product); ok {
			return p, true
		}
	}
	return nil, false
}
